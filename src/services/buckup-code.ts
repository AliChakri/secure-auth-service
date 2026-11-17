import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export interface GeneratedBackupCode {
    code: string;
    used: boolean;
    usedAt: Date | null;
}

export interface StoredBackupCode {
    code?: string;
    codeHash?: string;
    used?: boolean;
    usedAt?: Date | null;
}

export const generateBackupCodes = () => {
    const rawCodes: string[] = [];
    const hashedCodes: GeneratedBackupCode[] = [];

    for (let i = 0; i < 5; i++) {
        const raw = crypto
            .randomBytes(4)
            .toString('hex');
        rawCodes.push(raw);

        hashedCodes.push({
            code: bcrypt.hashSync(raw, 10),
            used: false,
            usedAt: null,
        });
    }

    return { rawCodes, hashedCodes };
};

export const verifyBackupCode = async (
    inputCode: string,
    storedCodes: Array<{ code?: string; codeHash?: string; used?: boolean; usedAt?: Date | null }>
) => {
    for (const item of storedCodes) {
        if (item.used || item.usedAt) continue;

        const hash = item.codeHash || item.code;
        if (!hash) continue;

        const match = await bcrypt.compare(inputCode, hash);
        if (match) return item;
    }
    return null;
};
