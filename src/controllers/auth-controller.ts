import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import { eq, and, sql } from 'drizzle-orm';

import { db } from '../database/index.js';
import { users, type User } from '../database/schema/users.schema.js';
import { authAccounts } from '../database/schema/auth/auth-accounts.schema.js';
import { userTwoFactor } from '../database/schema/auth/two-factor.schema.js';

import { AppError } from '../utils/AppError.js';
import { generateOtp, hashOtp } from '../utils/otp.js';
import redisClient from '../config/redis.js';
import { generateTempToken, verifyTempToken } from '../security/temp-token.js';
import { generateAccessToken, generateRefreshToken } from '../security/token-security.js';
import { verifyGoogleToken } from '../utils/google-verify.js';
import { incrementOtpAttempts, isOtpBlocked, clearOtpAttempts } from '../security/otp-security.js';
import { handleOAuthRecoveryCallback } from './2fa-controller.js';

interface MyTokenPayload extends JwtPayload {
    id: string;
}

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? ('strict' as const) : ('lax' as const),
    path: '/',
};

/**
 * Strips passwordHash and attaches compatibility alias (_id = id)
 */
export const sanitizeUser = (user: User, extra?: { authProvider?: string; twoFactorEnabled?: boolean }) => {
    const { passwordHash, ...safeUser } = user;
    return {
        ...safeUser,
        _id: safeUser.id,
        authProvider: extra?.authProvider ?? 'local',
        twoFactor: {
            enabled: extra?.twoFactorEnabled ?? false,
        },
    };
};

export const register = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return next(new AppError('Missing Fields!', 400));
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // Check if user already exists (case-insensitive)
    const [existingUser] = await db
        .select()
        .from(users)
        .where(eq(users.email, normalizedEmail))
        .limit(1);


    if (existingUser) {
        return next(new AppError('User Already exists', 400));
    }

    // Password hashing
    const hashedPassword = await bcrypt.hash(password, 12);

    // Atomic creation of user, auth account, and 2FA record
    const newUser = await db.transaction(async (tx) => {
        const [createdUser] = await tx
            .insert(users)
            .values({
                name: String(name).trim(),
                email: normalizedEmail,
                passwordHash: hashedPassword,
                isVerified: false,
            })
            .returning();

        await tx.insert(authAccounts).values({
            userId: createdUser.id,
            provider: 'local',
            providerUserId: null,
        });

        await tx.insert(userTwoFactor).values({
            userId: createdUser.id,
            enabled: false,
        });

        return createdUser;
    });

    // Create OTP and hash it
    const otp = generateOtp();
    const hashedOtp = hashOtp(otp);

    // Store OTP in Redis (TTL: 10 minutes)
    await redisClient.set(
        `verify:otp:${newUser.id}`,
        hashedOtp,
        { EX: 600 }
    );

    // Dev logging (keep email service call ready)
    console.log(`[Email Verification OTP for ${newUser.email}]:`, otp);

    res.status(201).json({
        status: 'success',
        message: 'User Registered. Verify Your Email',
        data: newUser.id,
    });
};

export const verifyEmail = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return next(new AppError('Missing Fields', 400));
    }

    const attemptKey = `verify:attempts:${userId}`;
    if (await isOtpBlocked(attemptKey)) {
        return next(new AppError('Too many OTP attempts. Try later.', 429));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    if (user.isVerified) {
        res.status(200).json({
            status: 'success',
            message: 'Email Already Verified',
        });
        return;
    }

    const hashedOtp = hashOtp(String(otp).trim());
    const storedOtp = await redisClient.get(`verify:otp:${userId}`);

    if (!storedOtp || String(storedOtp) !== String(hashedOtp)) {
        await incrementOtpAttempts(attemptKey);
        return next(new AppError('Invalid or Expired OTP', 400));
    }

    await clearOtpAttempts(attemptKey);
    await redisClient.del(`verify:otp:${userId}`);

    await db
        .update(users)
        .set({
            isVerified: true,
            updatedAt: new Date(),
        })
        .where(eq(users.id, userId));

    res.status(200).json({
        status: 'success',
        message: 'Email Verified Successfully',
    });
};

export const login = async (
    req: Request,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const { email, password } = req.body;

    if (!email || !password) {
        return next(new AppError('Missing Fields!', 400));
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const [user] = await db
        .select()
        .from(users)
        .where(eq(sql`lower(${users.email})`, normalizedEmail))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    // Check if user has a local password account
    const [localAccount] = await db
        .select()
        .from(authAccounts)
        .where(and(eq(authAccounts.userId, user.id), eq(authAccounts.provider, 'local')))
        .limit(1);

    if (!localAccount || !user.passwordHash) {
        return next(new AppError('Use Google login for this Account', 400));
    }

    const matchedPassword = await bcrypt.compare(password, user.passwordHash);
    if (!matchedPassword) {
        return next(new AppError('Incorrect Password', 400));
    }

    if (!user.isVerified) {
        return next(new AppError('Unauthorized. Verify Your Email First', 401));
    }

    // Check 2FA status
    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (twoFactorRecord?.enabled) {
        const tempToken = generateTempToken(user.id);
        res.status(200).json({
            status: 'success',
            message: '2FA Enabled. Verify to complete login.',
            twoFactorRequired: true,
            tempToken,
            data: user.email,
        });
        return;
    }

    // Standard session login
    const accessToken = generateAccessToken(user.id);
    const refreshToken = await generateRefreshToken(user.id);

    res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000,
    });

    res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
        status: 'success',
        message: `Welcome Back ${user.name}`,
        data: sanitizeUser(user, { authProvider: 'local', twoFactorEnabled: false }),
    });
};

export const googleLogin = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { idToken } = req.body;

    if (!idToken) {
        return next(new AppError('Google Token is required', 400));
    }

    const payload = await verifyGoogleToken(idToken);
    const { sub, email, name, picture } = payload;

    if (!email) {
        return next(new AppError('Google Account does not have an email address', 400));
    }

    // ── 2FA recovery re-auth: runs before any linking, user creation or login
    const recovered = await handleOAuthRecoveryCallback(req, res, next, {
        provider: 'google',
        providerAccountId: sub,
        email,
    });

    if (recovered) {
        res.status(200).json({
            status: 'success',
            recovered: true,
            message: '2FA has been disabled. You can now log in and set it up again.',
        });
        return;
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if user exists
    let [user] = await db
        .select()
        .from(users)
        .where(eq(sql`lower(${users.email})`, normalizedEmail))
        .limit(1);

    if (user) {
        // Query user's auth accounts
        const accounts = await db
            .select()
            .from(authAccounts)
            .where(eq(authAccounts.userId, user.id));

        const hasGoogle = accounts.some((a) => a.provider === 'google');
        const hasLocal = accounts.some((a) => a.provider === 'local');

        if (!hasGoogle && hasLocal) {
            return next(new AppError('Email Already registered with password login', 400));
        }

        // Link Google if not linked yet
        if (!hasGoogle) {
            await db.insert(authAccounts).values({
                userId: user.id,
                provider: 'google',
                providerUserId: sub,
            });
        }
    } else {
        // Create new user with Google account inside a transaction
        user = await db.transaction(async (tx) => {
            const [createdUser] = await tx
                .insert(users)
                .values({
                    name: name || 'Google User',
                    email: normalizedEmail,
                    avatar: picture || '',
                    isVerified: true,
                    passwordHash: null,
                })
                .returning();

            await tx.insert(authAccounts).values({
                userId: createdUser.id,
                provider: 'google',
                providerUserId: sub,
            });

            await tx.insert(userTwoFactor).values({
                userId: createdUser.id,
                enabled: false,
            });

            return createdUser;
        });
    }

    // Check 2FA
    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (twoFactorRecord?.enabled) {
        const tempToken = generateTempToken(user.id);
        res.status(200).json({
            status: 'success',
            twoFactorRequired: true,
            message: '2FA Enabled. Verify to complete login.',
            tempToken,
            data: user.email,
        });
        return;
    }

    const accessToken = generateAccessToken(user.id);
    const refreshToken = await generateRefreshToken(user.id);

    res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000,
    });

    res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
        status: 'success',
        message: `Welcome ${user.name}`,
        data: sanitizeUser(user, { authProvider: 'google', twoFactorEnabled: false }),
    });
};

export const verifyLogin2FA = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { tempToken, token } = req.body;

    if (!tempToken || !token) {
        return next(new AppError('Missing Fields', 400));
    }

    // Verify and decode temp token
    const userId = verifyTempToken(tempToken);

    // Prevent token replay attacks
    const isAlreadyUsed = await redisClient.get(`2fa-used:${tempToken}`);
    if (isAlreadyUsed) {
        return next(new AppError('Temporary session token expired or already used', 401));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, userId))
        .limit(1);

    if (!user || !twoFactorRecord?.enabled || !twoFactorRecord.secretEncrypted) {
        return next(new AppError('Unauthorized: 2FA not enabled', 401));
    }

    const isValid = speakeasy.totp.verify({
        secret: twoFactorRecord.secretEncrypted,
        encoding: 'base32',
        token: String(token).trim(),
        window: 1,
    });

    if (!isValid) {
        return next(new AppError('Invalid 2FA Code', 400));
    }

    // Invalidate the temp token
    await redisClient.set(`2fa-used:${tempToken}`, '1', { EX: 300 });

    const [account] = await db
        .select()
        .from(authAccounts)
        .where(eq(authAccounts.userId, user.id))
        .limit(1);

    const accessToken = generateAccessToken(user.id);
    const refreshToken = await generateRefreshToken(user.id);

    res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000,
    });

    res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
        status: 'success',
        message: `Welcome Back ${user.name}`,
        data: sanitizeUser(user, {
            authProvider: account?.provider || 'local',
            twoFactorEnabled: true,
        }),
    });
};

export const logout = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const token = req.cookies?.accessToken;

    if (!token) {
        return next(new AppError('Already Logged Out', 400));
    }

    const decoded = jwt.decode(token) as MyTokenPayload | null;

    if (!decoded || !decoded.id) {
        return next(new AppError('Invalid token structure', 400));
    }

    const userId = decoded.id;

    // Blacklist access token until its natural expiration
    if (decoded.exp) {
        const ttl = decoded.exp - Math.floor(Date.now() / 1000);
        if (ttl > 0) {
            await redisClient.setEx(`bl:${token}`, ttl, 'true');
            await redisClient.setEx(`blacklist:${token}`, ttl, 'true');
        }
    }

    // Invalidate refresh token in Redis
    await redisClient.del(`refresh:${userId}`);

    res.clearCookie('accessToken', cookieOptions);
    res.clearCookie('refreshToken', cookieOptions);

    res.status(200).json({
        status: 'success',
        message: 'Logged Out successfully',
    });
};

export const forgotPassword = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { email } = req.body;

    if (!email) {
        return next(new AppError('Email Address is Required', 400));
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const [user] = await db
        .select()
        .from(users)
        .where(eq(sql`lower(${users.email})`, normalizedEmail))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    const [localAccount] = await db
        .select()
        .from(authAccounts)
        .where(and(eq(authAccounts.userId, user.id), eq(authAccounts.provider, 'local')))
        .limit(1);

    if (!localAccount || !user.passwordHash) {
        return next(new AppError('Password reset not available for Google accounts', 400));
    }

    const otp = generateOtp();
    const hashedOtp = hashOtp(otp);

    // Store in Redis (TTL: 10 minutes)
    await redisClient.set(
        `reset:otp:${user.id}`,
        hashedOtp,
        { EX: 600 }
    );

    console.log(`[Forgot Password OTP for ${user.email}]:`, otp);

    res.status(200).json({
        status: 'success',
        message: 'Password Reset OTP sent to your email.',
        data: user.id,
    });
};

export const resetPassword = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { userId, otp, password, confirmPassword } = req.body;

    if (!userId || !otp || !password || !confirmPassword) {
        return next(new AppError('Missing Fields', 400));
    }

    if (password !== confirmPassword) {
        return next(new AppError('Passwords do not match', 400));
    }

    const attemptKey = `verify:attempts:${userId}`;
    if (await isOtpBlocked(attemptKey)) {
        return next(new AppError('Too many OTP attempts. Try later.', 429));
    }

    const hashedOtp = hashOtp(String(otp).trim());
    const storedOtp = await redisClient.get(`reset:otp:${userId}`);

    if (!storedOtp || storedOtp !== hashedOtp) {
        await incrementOtpAttempts(attemptKey);
        return next(new AppError('Invalid or expired OTP', 400));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await db
        .update(users)
        .set({
            passwordHash: hashedPassword,
            updatedAt: new Date(),
        })
        .where(eq(users.id, userId));

    // Cleanup Redis security data
    await redisClient.del(`reset:otp:${userId}`);
    await redisClient.del(`refresh:${userId}`);
    await clearOtpAttempts(attemptKey);

    res.clearCookie('accessToken', cookieOptions);
    res.clearCookie('refreshToken', cookieOptions);

    res.status(200).json({
        status: 'success',
        message: 'Password Reset Successfully.',
    });
};

export const changePassword = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { password, newPassword } = req.body;

    const currentUserId = req.user?.id || req.user?._id;
    if (!currentUserId) {
        return next(new AppError('Not authenticated', 401));
    }

    if (!password || !newPassword) {
        return next(new AppError('Missing password fields', 400));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, currentUserId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    if (!user.passwordHash) {
        return next(new AppError('Password changes only available for local accounts', 400));
    }

    const isMatched = await bcrypt.compare(password, user.passwordHash);
    if (!isMatched) {
        return next(new AppError('Current Password is Incorrect', 400));
    }

    const isSameAsCurrent = await bcrypt.compare(newPassword, user.passwordHash);
    if (isSameAsCurrent) {
        return next(new AppError('New Password Cannot Match Current Password', 400));
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await db
        .update(users)
        .set({
            passwordHash: hashedPassword,
            updatedAt: new Date(),
        })
        .where(eq(users.id, user.id));

    await redisClient.del(`refresh:${user.id}`);

    // Clear cookies to force re-login
    res.clearCookie('accessToken', cookieOptions);
    res.clearCookie('refreshToken', cookieOptions);

    res.status(200).json({
        status: 'success',
        message: 'Password Changed Successfully.',
    });
};

export const refreshToken = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const token = req.cookies?.refreshToken;

    if (!token) {
        return next(new AppError('No refresh Token', 401));
    }

    let decoded: MyTokenPayload;
    try {
        decoded = jwt.verify(
            token,
            process.env.JWT_REFRESH_SECRET!
        ) as MyTokenPayload;
    } catch {
        return next(new AppError('Invalid or expired refresh token', 401));
    }

    if (!decoded || !decoded.id) {
        return next(new AppError('Invalid token structure', 400));
    }

    const userId = decoded.id;
    const stored = await redisClient.get(`refresh:${userId}`);

    if (stored !== token) {
        return next(new AppError('Token Revoked', 403));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

    if (!user) {
        return next(new AppError('User no longer exists', 401));
    }

    const newAccessToken = generateAccessToken(userId);

    res.cookie('accessToken', newAccessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000,
    });

    res.status(200).json({
        status: 'success',
    });
};

export const me = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const currentUserId = req.user?.id || req.user?._id;
    if (!currentUserId) {
        res.status(200).json({
            status: 'success',
            data: null,
        });
        return;
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, currentUserId))
        .limit(1);

    if (!user) {
        return next(new AppError('User not Found', 404));
    }

    const [account] = await db
        .select()
        .from(authAccounts)
        .where(eq(authAccounts.userId, user.id))
        .limit(1);

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    res.status(200).json({
        status: 'success',
        data: sanitizeUser(user, {
            authProvider: account?.provider || 'local',
            twoFactorEnabled: !!twoFactorRecord?.enabled,
        }),
    });
};
