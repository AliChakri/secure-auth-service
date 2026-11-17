
import { OAuth2Client } from 'google-auth-library';
import { AppError } from './AppError.js';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const verifyGoogleToken = async (idToken:string) => {
    try {
        const ticket = await client.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();

        if (!payload) {
            throw new AppError('Invalid Google Token', 401);
        }

        return payload;
    } catch (error) {
        throw new AppError('Google Authentication failed', 401);
    }
};