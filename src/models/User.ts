import bcrypt from 'bcryptjs';
import { Schema, model, Document, Types } from 'mongoose';

/* ===================== TYPES ===================== */

export interface IRecoveryToken {
  token: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface IBackupCode {
  code: string;
  used: boolean;
  usedAt: Date | null;
}

export interface ITwoFactor {
  enabled: boolean;
  secret: string;
  verifiedAt: Date | null;
  tempSecret?: string;
  backupCodes: IBackupCode[];
  backupCodesGeneratedAt: Date | null;
}

export interface IUser extends Document<Types.ObjectId> {
  name: string;
  email: string;
  password?: string;
  authProvider: 'local' | 'google';
  googleId?: string;
  avatar: string;
  isVerified: boolean;

  twoFactor: ITwoFactor;
  recoveryTokens: IRecoveryToken[];

  comparePassword(candidatePassword: string): Promise<boolean>;
}

/* ===================== SCHEMA ===================== */

const recoveryTokenSchema = new Schema<IRecoveryToken>(
  {
    token: { type: String, required: true, select: false },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const userSchema = new Schema<IUser>(
  {
    name: { type: String, required: true, trim: true },

    email: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      index: true,
    },

    authProvider: {
      type: String,
      enum: ['local', 'google'],
      default: 'local',
    },

    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },

    password: {
      type: String,
      select: false,
    },

    avatar: {
      type: String,
      default: '',
    },

    isVerified: {
      type: Boolean,
      default: false,
    },

    twoFactor: {
      
      enabled: { type: Boolean, default: false },
      secret: { type: String, select: false },
      verifiedAt: { type: Date, default: null },
      tempSecret: { type: String },
      backupCodes: [
        {
          code: { type: String },
          used: { type: Boolean, default: false },
          usedAt: { type: Date, default: null },
        },
      ],
      backupCodesGeneratedAt: { type: Date, default: null },
    },

    recoveryTokens: {
      type: [recoveryTokenSchema],
      default: [],
      select: false,
    },
  },
  { timestamps: true }
);

/* ===================== METHODS ===================== */

userSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

export const User = model<IUser>('User', userSchema);
