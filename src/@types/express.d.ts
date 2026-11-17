import { ipKeyGenerator } from 'express-rate-limit';
import { User } from '../database/schema/users.schema.js';

export interface AuthenticatedUser extends User {
    _id?: string;
    authProvider?: string;
}

declare global {
    namespace Express {
        interface Request {
            user?: AuthenticatedUser;
            ip?: ipKeyGenerator;
        }
    }
}

export {};
