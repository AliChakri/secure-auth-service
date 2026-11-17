import rateLimit, { RateLimitInfo } from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import redisClient from "../config/redis.js";
import { AppError } from "../utils/AppError.js";

interface LimiterOptions {
    windowMs: number;
    limit: number;
    keyPrefix: string
}

const createRateLimiter = ({ windowMs, limit, keyPrefix }: LimiterOptions) => {
    return rateLimit({
        store: new RedisStore({
            sendCommand: async (...args: string[]) => {
                if (!redisClient.isOpen) {
                    // This prevents the "ClientClosedError"
                    await redisClient.connect().catch(() => {}); 
                }
                return redisClient.sendCommand(args);
            }, 
            prefix: keyPrefix,
        }),
        windowMs,
        limit,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res, next) => {
            next(new AppError('Too Many requests, please try again later.', 429));
        }
    });
};

// ----- Auth Specific Limiters -----
export const loginLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    keyPrefix: `rl:login`
});

export const registerLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000,
    limit: 3,
    keyPrefix: "rl:register"
});

export const gooleOAuthLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    keyPrefix: "rl:googleauth"
});

export const otpLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000,
    limit: 5,
    keyPrefix: "rl:otp"
});

export const twoFALoginLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  keyPrefix: "rl:2fa-login",
});

export const twoFAVerifyLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  keyPrefix: "rl:2fa-verify",
});

export const twoFADisableLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 3,
  keyPrefix: "rl:2fa-disable",
});

export const BuckupCodeLoginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyPrefix: "rl:buckup-code-login",
});

export const GetBuckupCodeLimiter = createRateLimiter({
  windowMs: 30 * 60 * 1000,
  limit: 10,
  keyPrefix: "rl:buckup-code-get",
});

export const RegenerateBuckupCodeLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyPrefix: "rl:buckup-code-regenerate",
});

export const RequestRecoveryLinkLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  keyPrefix: "rl:recovery-link-request",
});

export const VerifyRecoveryLinkLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyPrefix: "rl:recovery-link-verify",
});