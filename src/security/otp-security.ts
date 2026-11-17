import redisClient from "../config/redis.js";

const MAX_ATTEMPTS = 5;
const TTL = 600;

export const incrementOtpAttempts = async (key: string) => {
    const attempts = await redisClient.incr(key);

    if (attempts === 1) {
        await redisClient.expire(key, TTL);
    }

    return attempts;
};

export const clearOtpAttempts = async (key:string) => {
    await redisClient.del(key);
};

export const isOtpBlocked = async (key:string) => {
    const attempts = await redisClient.get(key);
    return attempts && parseInt(attempts) >= MAX_ATTEMPTS;
};