import 'dotenv/config'
import jwt, { JwtPayload } from 'jsonwebtoken';
import { AppError } from '../utils/AppError.js';

// interface TempTokenPayload extends JwtPayload {
//     id: string;
//     purpose: string;
// }

type TempTokenPurpose = '2fa-login' | '2fa-recovery';

interface TempTokenPayload {
    id: string;
    purpose: TempTokenPurpose;
}

export const generateTempToken = (
    userId: string,
    purpose: TempTokenPurpose = '2fa-login',
    expiresIn: jwt.SignOptions['expiresIn'] = '5m'
) => {
    const secret = process.env.TEMP_TOKEN_SECRET!;
    return jwt.sign(
        { id: userId, purpose },
        secret,
        {
            expiresIn,
            audience: '2fa',
            issuer: 'auth-service',
        }
    );
};

export const verifyTempToken = (
    token: string,
    expectedPurpose: TempTokenPurpose = '2fa-login'
): string => {
    try {
        const secret = process.env.TEMP_TOKEN_SECRET!;
        const payload = jwt.verify(token, secret, {
            audience: '2fa',
            issuer: 'auth-service',
        }) as TempTokenPayload;

        if (payload.purpose !== expectedPurpose) {
            throw new AppError('Invalid temp token purpose', 401);
        }

        return payload.id;
    } catch {
        throw new AppError('Invalid or expired temporary token', 401);
    }
};