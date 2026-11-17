
import jwt from 'jsonwebtoken'
import redisClient from '../config/redis.js';

export const generateAccessToken = (userId: string) => {
    return jwt.sign(
        { id: userId },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: '15m' }
    );
};

export const generateRefreshToken = async (userId:string) => {
    const token = jwt.sign(
        { id: userId },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '7d' }
    );
    
    // Store in Redis
    await redisClient.set(
        `refresh:${userId}`,
        token,
        { EX: 7 * 24 * 60 * 60 }
    );

    return token;
};