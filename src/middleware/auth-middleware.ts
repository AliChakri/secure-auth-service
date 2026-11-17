import { eq } from "drizzle-orm";
import jwt from "jsonwebtoken";
import { db } from "../database/index.js";
import { users } from "../database/schema/users.schema.js";
import { authAccounts } from "../database/schema/auth/auth-accounts.schema.js";
import { isBlacklisted } from "../services/blacklist-service.js";
import { catchAsync } from "../utils/catchAsync.js";
import { NextFunction, Request, Response } from "express";
import { AppError } from "../utils/AppError.js";

interface AccessTokenPayload extends jwt.JwtPayload {
    id: string;
}

export const protect = catchAsync(async (
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    const accessToken = req.cookies?.accessToken;
    if (!accessToken) {
        return next(new AppError('Not authenticated. Please log in.', 401));
    }

    const blacklisted = await isBlacklisted(accessToken);
    if (blacklisted) {
        return next(new AppError('Session revoked. Please log in again.', 401));
    }

    try {
        const decoded = jwt.verify(
            accessToken,
            process.env.JWT_ACCESS_SECRET!,
        ) as AccessTokenPayload;

        if (!decoded?.id) {
            return next(new AppError('Invalid token payload.', 401));
        }

        const [user] = await db
            .select()
            .from(users)
            .where(eq(users.id, decoded.id))
            .limit(1);

        if (!user) {
            return next(new AppError('The user belonging to this token no longer exists.', 401));
        }

        if (!user.isVerified) {
            return next(new AppError('Please verify your email to access this resource.', 403));
        }

        const [account] = await db
            .select()
            .from(authAccounts)
            .where(eq(authAccounts.userId, user.id))
            .limit(1);

        req.user = {
            ...user,
            _id: user.id,
            authProvider: account?.provider || 'local',
        };

        next();

    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return next(new AppError('Your session has expired. Please refresh your token.', 401));
        }
        return next(new AppError('Invalid token. Access denied.', 401));
    }
});
