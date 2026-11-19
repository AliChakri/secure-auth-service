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
import { generateTempToken, verifyTempToken } from "../security/temp-token.js";
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

    const [twoFactorRecord] = await db
        .select()
        .from(userTwoFactor)
        .where(eq(userTwoFactor.userId, user.id))
        .limit(1);

    if (!twoFactorRecord?.enabled || !twoFactorRecord.secretEncrypted) {
        return next(new AppError('Two Factor Authentication not enabled', 400));
    }

    // Check count of remaining unused codes (must be >= 3 to allow regeneration)
    const unusedCodes = await db
        .select()
        .from(twoFactorBackupCodes)
        .where(and(eq(twoFactorBackupCodes.userId, user.id), isNull(twoFactorBackupCodes.usedAt)));

    if (unusedCodes.length >= 3) {
        return next(
            new AppError(
                `Must have at least 3 backup codes remaining to regenerate. You currently have ${unusedCodes.length}.`,
                400
            )
        );
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
        return next(new AppError('Email address is required', 400));
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const [user] = await db
        .select()
        .from(users)
        .where(eq(sql`lower(${users.email})`, normalizedEmail))
        .limit(1);

    if (user) {

        const [twoFactorRecord] = await db
            .select()
            .from(userTwoFactor)
            .where(eq(userTwoFactor.userId, user.id))
            .limit(1);

        if (twoFactorRecord?.enabled) {
            const rawToken = crypto.randomBytes(32).toString('hex');
            const hashedToken = hashOtp(rawToken); // SHA-256 hash helper

            await redisClient.set(
                `2fa-recovery-token:${user.id}`,
                hashedToken,
                { EX: 600 }
            );

            await db.insert(recoveryTokens).values({
                userId: user.id,
                tokenHash: hashedToken,
                expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            });

            const recoveryUrl = `${process.env.FRONTEND_URL}/settings/security/2fa/recovery/verify?token=${rawToken}&email=${encodeURIComponent(user.email)}`;
            console.log(`[2FA Recovery Link for ${user.email}]:`, recoveryUrl);
            // await sendRecoveryEmail(user.email, recoveryUrl);
        }
    }

    // Return generic 200 to prevent email enumeration
    res.status(200).json({
        status: 'success',
        message: 'If an eligible account exists, a recovery link has been sent.',
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

    const hashedToken = hashOtp(String(token).trim());

    // 1. Validate recovery link token (Redis -> Postgres fallback)
    const recoveryTokenFromRedis = await redisClient.get(`2fa-recovery-token:${user.id}`);
    let isTokenValid = recoveryTokenFromRedis === hashedToken;

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

        if (dbToken) isTokenValid = true;
    }

    if (!isTokenValid) {
        return next(new AppError('Invalid or expired recovery link', 401));
    }

    // 2. Check linked auth methods
    const accounts = await db
        .select()
        .from(authAccounts)
        .where(eq(authAccounts.userId, user.id));

    const localAccount = accounts.find((acc) => acc.provider === 'local');
    const oauthAccount = accounts.find((acc) => acc.provider !== 'local');

    // CASE A: Local user -> verify password and disable 2FA immediately
    if (localAccount && user.passwordHash) {
        if (!password) {
            return next(new AppError('Password is required for local accounts', 400));
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordCorrect) {
            return next(new AppError('Invalid password', 401));
        }

        await redisClient.del(`2fa-recovery-token:${user.id}`);

        await db.transaction(async (tx) => {
            await tx
                .update(recoveryTokens)
                .set({ usedAt: new Date() })
                .where(
                    and(
                        eq(recoveryTokens.userId, user.id),
                        eq(recoveryTokens.tokenHash, hashedToken),
                        isNull(recoveryTokens.usedAt)
                    )
                );

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
            requiresOAuthReauth: false,
            message: '2FA has been disabled. You can now log in and set it up again.',
        });
        return;
    }

    // CASE B: OAuth-only user -> bind a short-lived recovery session & require IdP re-auth
    if (!oauthAccount) {
        return next(new AppError('No valid authentication method found for recovery', 400));
    }

    const recoverySessionToken = generateTempToken(user.id, '2fa-recovery', '10m');

    // Store hashedToken in Redis tied to this recovery session so OAuth callback can consume it
    await redisClient.set(
        `2fa-recovery-session:${user.id}`,
        hashedToken,
        { EX: 600 }
    );

    res.cookie('recoverySession', recoverySessionToken, {
        ...cookieOptions,
        maxAge: 10 * 60 * 1000,
    });

    res.status(200).json({
        status: 'success',
        requiresOAuthReauth: true,
        provider: oauthAccount.provider, // e.g., 'google' | 'github'
        message: 'Recovery link verified. Please re-authenticate with your OAuth provider to disable 2FA.',
    });
};

export const handleOAuthRecoveryCallback = async (
    req: Request,
    res: Response,
    next: NextFunction,
    oauthProfile: { provider: string; providerAccountId: string; email: string }
): Promise<boolean> => {
    const recoveryCookie = req.cookies?.recoverySession;
    if (!recoveryCookie) return false; // Not a 2FA recovery flow -> proceed with normal OAuth login

    // 1. Verify the recoverySession JWT
    const userId = verifyTempToken(recoveryCookie, '2fa-recovery');

    // 2. Ensure the pending recovery session still exists in Redis
    const hashedToken = await redisClient.get(`2fa-recovery-session:${userId}`);
    if (!hashedToken) {
        throw new AppError('Recovery session expired. Please restart 2FA recovery.', 401);
    }

    // 3. Verify that the OAuth provider + providerAccountId (sub) match this exact user
    const [matchedAccount] = await db
        .select()
        .from(authAccounts)
        .where(
            and(
                eq(authAccounts.userId, userId),
                eq(authAccounts.provider, oauthProfile.provider),
                eq(authAccounts.providerUserId, oauthProfile.providerAccountId)
            )
        )
        .limit(1);

    if (!matchedAccount) {
        throw new AppError('OAuth account does not match the account being recovered', 403);
    }

    // 4. Consume recovery token, clear cookies/Redis, and disable 2FA
    await redisClient.del(`2fa-recovery-token:${userId}`);

    await db.transaction(async (tx) => {
        await tx
            .update(recoveryTokens)
            .set({ usedAt: new Date() })
            .where(
                and(
                    eq(recoveryTokens.userId, userId),
                    eq(recoveryTokens.tokenHash, hashedToken),
                    isNull(recoveryTokens.usedAt)
                )
            );

        await tx
            .update(userTwoFactor)
            .set({
                enabled: false,
                secretEncrypted: null,
                tempSecretEncrypted: null,
                verifiedAt: null,
                backupCodesGeneratedAt: null,
            })
            .where(eq(userTwoFactor.userId, userId));

        await tx
            .delete(twoFactorBackupCodes)
            .where(eq(twoFactorBackupCodes.userId, userId));
    });

    await redisClient.del(`2fa-recovery-session:${userId}`);
    res.clearCookie('recoverySession', cookieOptions);

    return true; // Caller can now issue normal auth tokens & redirect to /settings/security
};
