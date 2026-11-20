import z, { string } from "zod";

// Shared password requirements
const passwordSchema = z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain one uppercase letter')
    .regex(/[0-9]/, 'Password must contain one number');

const otpCodeSchema = z.string()
  .length(6, "2FA code must be 6 digits")
  .regex(/^\d+$/, "2FA code must contain only numbers");    

export const registerSchema = z.object({
    body: z.object({
        name: z.string().min(2, 'Name is too short').trim(),
        email: z.string().email('Invalid email address').trim().lowercase(),
        password: passwordSchema
    })
});

export const loginSchema = z.object({
    body: z.object({
        email: z.string().email().trim().lowercase(),
        password: z.string().min(1, 'Password is required'),
    })
});

export const otpSchema = z.object({
    body: z.object({
        userId: z.string(),
        otp: z.string().length(6),
    })
});

export const resetPasswordSchema = z.object({
    body: z.object({
        userId: z.string(),
        otp: z.string().length(6),
        password: z.string().min(8),
        confirmPassword: z.string().min(8)
    })
});

export const verifyLogin2FASchema = z.object({
    body: z.object({
        tempToken: z.string().min(20, "Invalid session token"),
        token: z.string().length(6, "2FA code must be 6 digits"),
    })
});

export const verify2FASchema = z.object({
    token: z.string()
        .length(6, "2FA code must be 6 digits"),
});

export const disable2FASchema = z.object({
    body: z.object({
        password: z.string()
        .min(8),
        token: z.string()
            .length(6, "2FA code must be 6 digits"),
    })
});

export const twoFAVerifySchema = z.object({
    body: z.object({
        token: z.string().length(6, "2FA code must be 6 digits"),
    })
});

export const BuckupCodeLoginSchema = z.object({
    body: z.object({
        token: z.string()
                .length(8, "Buckup code must be 8 digits"),
        tempToken: z.string()
                .min(8),
    })
});

export const RegenerateBuckupCodeSchema = z.object({
    body: z.object({
        password: z.preprocess(
            (val) => (val === '' || val === undefined ? undefined : val),
            passwordSchema.optional()
        ),

        token: otpCodeSchema,
    })
});

export const VerifyRecoveryLinkSchema = z.object({
    body: z.object({
        token: z.string().min(6, "Token otp must be 6"),
        email: z.string().email(),
        password: passwordSchema.optional()
    }),
});

export const EmailShcema = z.object({
    body: z.object({
        email: z.string().email(),
    })
});

export const backupCodeSchema = z.object({
    tempToken: z.string().min(10),
    backupCode: z.string().min(8),
});

export type RegisterBody = z.infer<typeof registerSchema>['body'];
export type LoginBody = z.infer<typeof loginSchema>['body'];