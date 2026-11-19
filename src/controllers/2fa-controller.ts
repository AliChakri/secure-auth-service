import { NextFunction, Request, Response } from "express";
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import bcrypt from 'bcryptjs';
import { eq, and, isNull, sql, asc, gt } from 'drizzle-orm';

import { db } from '../database/index.js';
import { users } from '../database/schema/users.schema.js';
import { authAccounts } from '../database/schema/auth/auth-accounts.schema.js';
import { userTwoFactor } from '../database/schema/auth/two-factor.schema.js';
import { twoFactorBackupCodes } from '../database/schema/auth/buckup-codes.schema.js';
import { recoveryTokens } from '../database/schema/auth/recovery-tokens.schema.js';

import { AppError } from "../utils/AppError.js";
import { twoFADisableLimiter, twoFAVerifyLimiter } from "../middleware/rate-limit-middleware.js";
import { generateBackupCodes } from "../services/buckup-code.js";
import { verifyTempToken } from "../security/temp-token.js";
import { generateAccessToken, generateRefreshToken } from "../security/token-security.js";
import redisClient from "../config/redis.js";
import { generateOtp, hashOtp } from "../utils/otp.js";
import { sanitizeUser } from "./auth-controller.js";

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? ('strict' as const) : ('lax' as const),
    path: '/',
};

export const setup2FA = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const currentUserId = req.user?.id || req.user?._id;

    if (!currentUserId) {
        return next(new AppError('User Not Found or Not Authenticated', 404));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, currentUserId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (twoFactorRecord?.enabled) {
        return next(new AppError('2FA Already Enabled', 400));
    }

    const secret = speakeasy.generateSecret({
        name: `Auth System (${user.email})`,
        length: 20,
    });

    if (!secret.otpauth_url || !secret.base32) {
        return next(new AppError('Failed to generate 2FA secret', 500));
    }

    // Upsert temporary secret into user_two_factor
    await db
        .insert(userTwoFactor)
        .values({
            userId: user.id,
            tempSecretEncrypted: secret.base32,
            enabled: false,
        })
        .onConflictDoUpdate({
            target: userTwoFactor.userId,
            set: {
                tempSecretEncrypted: secret.base32,
            },
        });

    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    res.status(200).json({
        status: 'success',
        message: '2FA setup initiated',
        qrCode,
        manualKey: secret.base32,
    });
};

export const verify2FA = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const currentUserId = req.user?.id || req.user?._id;

    if (!currentUserId) {
        return next(new AppError('Not authenticated', 401));
    }

    const { token } = req.body;
    if (!token) {
        return next(new AppError('Verification code is required', 400));
    }

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, currentUserId))
        .limit(1);

    if (!twoFactorRecord || !twoFactorRecord.tempSecretEncrypted) {
        return next(new AppError('2FA session expired or not initiated', 400));
    }

    const verified = speakeasy.totp.verify({
        secret: twoFactorRecord.tempSecretEncrypted,
        encoding: 'base32',
        token: String(token).trim(),
        window: 1,
    });

    if (!verified) {
        return next(new AppError('Invalid Code. Verification failed.', 400));
    }

    // Reset rate limiter
    const clientIp = req.ip || '127.0.0.1';
    try {
        twoFAVerifyLimiter.resetKey(String(clientIp));
    } catch {
        // Ignore rate-limit reset error if store doesn't support it
    }

    // Generate fresh backup codes
    const { rawCodes, hashedCodes } = generateBackupCodes();

    // Atomic update of 2FA state & backup codes storage
    await db.transaction(async (tx) => {
        // Purge any stale backup codes for this user
        await tx
            .delete(twoFactorBackupCodes)
            .where(eq(twoFactorBackupCodes.userId, currentUserId));

        // Insert new hashed backup codes
        if (hashedCodes.length > 0) {
            await tx.insert(twoFactorBackupCodes).values(
                hashedCodes.map((item) => ({
                    userId: currentUserId,
                    codeHash: item.code,
                    usedAt: null,
                }))
            );
        }

        const now = new Date();
        await tx
            .update(userTwoFactor)
            .set({
                secretEncrypted: twoFactorRecord.tempSecretEncrypted,
                tempSecretEncrypted: null,
                enabled: true,
                verifiedAt: now,
                backupCodesGeneratedAt: now,
            })
            .where(eq(userTwoFactor.userId, currentUserId));
    });

    res.status(200).json({
        status: 'success',
        message: '2FA enabled successfully',
        data: {
            backupCodes: rawCodes, // Returned ONCE upon initial generation
        },
    });
};

export const disable2FA = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const currentUserId = req.user?.id || req.user?._id;

    if (!currentUserId) {
        return next(new AppError('Not authenticated', 401));
    }

    const { password, token } = req.body;

    if (!token) {
        return next(new AppError('Verification code is required', 400));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, currentUserId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    // If local password account exists, strictly verify password
    const [localAccount] = await db
        .select()
        .from(authAccounts)
        .where(and(eq(authAccounts.userId, user.id), eq(authAccounts.provider, 'local')))
        .limit(1);

    if (localAccount && user.passwordHash) {
        if (!password) {
            return next(new AppError('Current password is required to disable 2FA', 400));
        }

        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return next(new AppError('Incorrect Password', 400));
        }
    }

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (!twoFactorRecord || !twoFactorRecord.enabled || !twoFactorRecord.secretEncrypted) {
        return next(new AppError('2FA is not enabled', 400));
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

    const clientIp = req.ip || '127.0.0.1';
    try {
        twoFADisableLimiter.resetKey(String(clientIp));
    } catch {
        // Ignore rate-limit reset error if store doesn't support it
    }

    // Transactionally disable 2FA and delete backup codes
    await db.transaction(async (tx) => {
        await tx
            .update(userTwoFactor)
            .set({
                enabled: false,
                secretEncrypted: null,
                tempSecretEncrypted: null,
                verifiedAt: null,
                backupCodesGeneratedAt: null,
            })
            .where(eq(userTwoFactor.userId, user.id));

        await tx
            .delete(twoFactorBackupCodes)
            .where(eq(twoFactorBackupCodes.userId, user.id));
    });

    res.status(200).json({
        status: 'success',
        message: '2FA Disabled',
    });
};

export const backup2FALogin = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { token: buckupCode, tempToken } = req.body;

    if (!buckupCode || !tempToken) {
        return next(new AppError('Missing Fields', 400));
    }

    const userId = verifyTempToken(tempToken);

    // Prevent temp token replay
    const isTokenUsed = await redisClient.get(`2fa-used:${tempToken}`);
    if (isTokenUsed) {
        return next(new AppError('Temporary token has expired or already been used', 401));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (!twoFactorRecord?.enabled) {
        return next(new AppError('Two Factor Authentication Not Activated', 400));
    }

    // Retrieve unused backup codes for user
    const unusedCodes = await db
        .select()
        .from(twoFactorBackupCodes)
        .where(and(eq(twoFactorBackupCodes.userId, user.id), isNull(twoFactorBackupCodes.usedAt)));

    if (unusedCodes.length === 0) {
        return next(new AppError('No unused backup codes found. Please use account recovery.', 400));
    }

    const normalizedBackupCode = String(buckupCode).trim().toLocaleLowerCase();

    let matchedCodeId: string | null = null;
    for (const item of unusedCodes) {
        const match = await bcrypt.compare(normalizedBackupCode, item?.codeHash);
        if (match) {
            matchedCodeId = item.id;
            break;
        }
    }

    if (!matchedCodeId) {
        return next(new AppError('Invalid or Used Backup Code', 400));
    }

    // Atomically mark backup code as used to prevent double-spending
    const updateResult = await db
        .update(twoFactorBackupCodes)
        .set({ usedAt: new Date() })
        .where(and(eq(twoFactorBackupCodes.id, matchedCodeId), isNull(twoFactorBackupCodes.usedAt)))
        .returning();

    if (updateResult.length === 0) {
        return next(new AppError('Backup code has already been used', 400));
    }

    // Invalidate temporary token
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
        message: `Welcome ${user.name}`,
        data: sanitizeUser(user, {
            authProvider: account?.provider || 'local',
            twoFactorEnabled: true,
        }),
    });
};

export const getBackupCodeStat = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const currentUserId = req.user?.id || req.user?._id;

    if (!currentUserId) {
        return next(new AppError('Unauthorized: Please login', 401));
    }

    const [twoFactorRecord] = await db
        .select({
            enabled: userTwoFactor.enabled,
            generatedAt: userTwoFactor.backupCodesGeneratedAt,
        })
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, currentUserId))
        .limit(1);

    if (!twoFactorRecord?.enabled) {
        return next(new AppError('Two Factor Authentication not enabled', 400));
    }

    const backupCodes = await db
        .select({
            usedAt: twoFactorBackupCodes.usedAt,
        })
        .from(twoFactorBackupCodes)
        .where(eq(twoFactorBackupCodes.userId, currentUserId));

    const total = backupCodes.length;
    const remaining = backupCodes.filter(
        code => code.usedAt === null
    ).length;

    res.status(200).json({
        status: 'success',
        data: {
            total,
            remaining,
            used: total - remaining,
            generatedAt: twoFactorRecord.generatedAt,
            shouldRegenerate: remaining <= 2,
        },
    });
};

export const regenerateBackupCode = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const currentUserId = req.user?.id || req.user?._id;

    if (!currentUserId) {
        return next(new AppError('Unauthorized: Please login and enable 2FA', 401));
    }

    const { password, token } = req.body;

    if (!token) {
        return next(new AppError('Token is Required', 400));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, currentUserId))
        .limit(1);

    if (!user) {
        return next(new AppError('User Not Found', 404));
    }

    // Verify password if local account
    const [localAccount] = await db
        .select()
        .from(authAccounts)
        .where(and(eq(authAccounts.userId, user.id), eq(authAccounts.provider, 'local')))
        .limit(1);

    if (localAccount && user.passwordHash) {
        if (!password) {
            return next(new AppError('Password is required to regenerate backup codes', 400));
        }
        const matched = await bcrypt.compare(password, user.passwordHash);
        if (!matched) {
            return next(new AppError('Invalid Password', 400));
        }
    }

    // Check count of remaining unused codes (must be >= 3 to allow regeneration)
    const unusedCodes = await db
        .select()
        .from(twoFactorBackupCodes)
        .where(and(eq(twoFactorBackupCodes.userId, user.id), isNull(twoFactorBackupCodes.usedAt)));

    if (unusedCodes.length < 3) {
        return next(
            new AppError(
                `Must have at least 3 backup codes remaining to regenerate. You currently have ${unusedCodes.length}.`,
                400
            )
        );
    }

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (!twoFactorRecord?.enabled || !twoFactorRecord.secretEncrypted) {
        return next(new AppError('Two Factor Authentication not enabled', 400));
    }

    const matched = speakeasy.totp.verify({
        secret: twoFactorRecord.secretEncrypted,
        encoding: 'base32',
        token: String(token).trim(),
        window: 1,
    });

    if (!matched) {
        return next(new AppError('Invalid Code', 400));
    }

    const { rawCodes, hashedCodes } = generateBackupCodes();

    // Atomic replacement of backup codes
    await db.transaction(async (tx) => {
        await tx
            .delete(twoFactorBackupCodes)
            .where(eq(twoFactorBackupCodes.userId, user.id));

        if (hashedCodes.length > 0) {
            await tx.insert(twoFactorBackupCodes).values(
                hashedCodes.map((item) => ({
                    userId: user.id,
                    codeHash: item.code,
                    usedAt: null,
                }))
            );
        }

        await tx
            .update(userTwoFactor)
            .set({
                backupCodesGeneratedAt: new Date(),
            })
            .where(eq(userTwoFactor.userId, user.id));
    });

    res.status(200).json({
        status: 'success',
        message: 'Backup Codes changed successfully',
        data: {
            backupCodes: rawCodes,
        },
    });
};

export const requestRecoveryLink = async (
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
        return next(new AppError('Enable Two Factor Authentication first', 400));
    }

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (!twoFactorRecord || !twoFactorRecord.enabled) {
        return next(new AppError('Enable Two Factor Authentication first', 400));
    }

    const otp = generateOtp();
    const hashedOtp = hashOtp(otp);

    // Store in Redis (TTL: 10 minutes)
    await redisClient.set(
        `2fa-recovery-otp:${user.id}`,
        hashedOtp,
        { EX: 600 }
    );

    // Also persist in recovery_tokens table
    await db.insert(recoveryTokens).values({
        userId: user.id,
        tokenHash: hashedOtp,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });

    console.log(`[2FA Recovery OTP for ${user.email}]:`, otp);

    res.status(200).json({
        status: 'success',
        message: 'recovery link has been sent to you',
    });
};

export const verifyRecoveryLink = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const { token, email, password } = req.body as {
        token: string;
        email: string;
        password?: string;
    };

    if (!token || !email) {
        return next(new AppError('Invalid request parameters', 400));
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const [user] = await db
        .select()
        .from(users)
        .where(eq(sql`lower(${users.email})`, normalizedEmail))
        .limit(1);

    if (!user) {
        return next(new AppError('Invalid or expired recovery link', 401));
    }

    // If account has local password, require and verify password
    const [localAccount] = await db
        .select()
        .from(authAccounts)
        .where(and(eq(authAccounts.userId, user.id), eq(authAccounts.provider, 'local')))
        .limit(1);

    if (localAccount && user.passwordHash) {
        if (!password) {
            return next(new AppError('Password is required for local accounts', 400));
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordCorrect) {
            return next(new AppError('Invalid password', 401));
        }
    }

    const hashedToken = hashOtp(String(token).trim());

    // Check Redis first
    const recoveryTokenFromRedis = await redisClient.get(`2fa-recovery-otp:${user.id}`);
    let isTokenValid = recoveryTokenFromRedis === hashedToken;

    // Fallback check against postgres recovery_tokens table
    if (!isTokenValid) {
        const [dbToken] = await db
            .select()
            .from(recoveryTokens)
            .where(
                and(
                    eq(recoveryTokens.userId, user.id),
                    eq(recoveryTokens.tokenHash, hashedToken),
                    isNull(recoveryTokens.usedAt),
                    gt(recoveryTokens.expiresAt, new Date())
                )
            )
            .limit(1);

        if (dbToken) {
            isTokenValid = true;
        }
    }

    if (!isTokenValid) {
        return next(new AppError('Invalid or expired recovery link', 401));
    }

    // Cleanup Redis and mark token as used in DB
    await redisClient.del(`2fa-recovery-otp:${user.id}`);
    await db
        .update(recoveryTokens)
        .set({ usedAt: new Date() })
        .where(and(eq(recoveryTokens.userId, user.id), eq(recoveryTokens.tokenHash, hashedToken)));

    // Atomically disable 2FA and delete backup codes
    await db.transaction(async (tx) => {
        await tx
            .update(userTwoFactor)
            .set({
                enabled: false,
                secretEncrypted: null,
                tempSecretEncrypted: null,
                verifiedAt: null,
                backupCodesGeneratedAt: null,
            })
            .where(eq(userTwoFactor.userId, user.id));

        await tx
            .delete(twoFactorBackupCodes)
            .where(eq(twoFactorBackupCodes.userId, user.id));
    });

    res.status(200).json({
        status: 'success',
        message: 'Recovery action completed. You can now login without 2FA and set it up again if you wish.',
    });
};
