import 'dotenv/config'
import jwt, { JwtPayload } from 'jsonwebtoken';
import { AppError } from '../utils/AppError.js';

interface TempTokenPayload extends JwtPayload {
    id: string;
    purpose: string;
}

export const generateTempToken = (userId: string) => {
    const secret = process.env.TEMP_TOKEN_SECRET!;
    return jwt.sign(
        {
            id: userId,
            purpose: '2fa-login',
        },
        secret, 
        {
            expiresIn: '5m',
            audience: "2fa",
            issuer: "auth-service"
        },
    );
};

export const verifyTempToken = (token: string): string => {
    try {
        const secret = process.env.TEMP_TOKEN_SECRET!;
        const payload = jwt.verify(token, secret, {
            audience: '2fa',
            issuer: 'auth-service'
        }) as TempTokenPayload;

        if (payload.purpose !== '2fa-login') {
            throw new AppError('Invalid temp Token purpose', 401);
        }

        return payload.id;

    } catch (error) {
        throw new AppError('Invalid or expired temporary token', 401);
    }
};