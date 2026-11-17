
import redisClient from "../config/redis.js";

export const blacklistToken = async (token: string, exp: number): Promise<void> => {
    const currentTime = Math.floor(Date.now() / 1000);
    const ttl = exp - currentTime;

    if (ttl > 0) {
        // Store the token as the key. "1" is just a dummy value.
        await redisClient.set(`bl:${token}`, "1", {
            EX: ttl
        });
    }
};

/**
 * Checks if a token exists in the Redis blacklist.
 */
export const isBlacklisted = async (token: string): Promise<boolean> => {
    const result = await redisClient.exists(`bl:${token}`);
    return result === 1;
};