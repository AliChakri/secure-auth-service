
import { Router } from 'express';

import { forgotPassword, googleLogin, login, logout, me, refreshToken, register, resetPassword, verifyEmail, verifyLogin2FA } from '../controllers/auth-controller.js';

import { BuckupCodeLoginLimiter, GetBuckupCodeLimiter, gooleOAuthLimiter, loginLimiter, otpLimiter, RegenerateBuckupCodeLimiter, registerLimiter, RequestRecoveryLinkLimiter, twoFADisableLimiter, twoFALoginLimiter, twoFAVerifyLimiter } from '../middleware/rate-limit-middleware.js';

import { validate } from '../middleware/validate-middleware.js';
import { BuckupCodeLoginSchema, disable2FASchema, EmailShcema, loginSchema, otpSchema, RegenerateBuckupCodeSchema, registerSchema, resetPasswordSchema, twoFAVerifySchema, verifyLogin2FASchema, VerifyRecoveryLinkSchema } from '../validators/auth-schema.js';
import { backup2FALogin, disable2FA, getBackupCodeStat, regenerateBackupCode, requestRecoveryLink, setup2FA, verify2FA, verifyRecoveryLink } from '../controllers/2fa-controller.js';
import { protect } from '../middleware/auth-middleware.js';

const authRouter: Router = Router();

// ----- Local Sign Up ----- 
authRouter.post(
    '/register',
    registerLimiter,
    validate(registerSchema),
    register
);

authRouter.post(
    '/verify-email',
    otpLimiter,
    validate(otpSchema),
    verifyEmail
);

// ----- Login in Diffrent Methods: 2FA, Local, Oauth -----
authRouter.post(
    '/login',
    loginLimiter,
    validate(loginSchema),
    login
);

authRouter.post(
    '/google',
    gooleOAuthLimiter,
    googleLogin
);

authRouter.post(
    '/2fa/login',
    twoFALoginLimiter,
    validate(verifyLogin2FASchema),
    verifyLogin2FA
);

// ----- Logout + Reseting/Changing Password -----
authRouter.post(
    '/logout',
    protect,
    logout
);

authRouter.post(
    '/forgot-password',
    otpLimiter,
    forgotPassword
);

authRouter.post(
    '/reset-password',
    validate(resetPasswordSchema),
    resetPassword
);

// ----- Two Factor Authentication (2FA) Routes -----

authRouter.post(
    '/2fa/setup',
    protect,
    setup2FA
);

authRouter.post(
    '/2fa/verify',
    protect,
    twoFAVerifyLimiter,
    validate(twoFAVerifySchema),
    verify2FA
);

authRouter.post(
    '/2fa/disable',
    protect,
    twoFADisableLimiter,
    validate(disable2FASchema),
    disable2FA
);

// ------ Recovery & Buckup Codes Routes
authRouter.post(
    '/2fa/login/verify-buckup',
    BuckupCodeLoginLimiter,
    validate(BuckupCodeLoginSchema),
    backup2FALogin
);

authRouter.post(
    '/2fa/buckup-code/stat',
    protect,
    GetBuckupCodeLimiter,
    validate(RegenerateBuckupCodeSchema),
    getBackupCodeStat
);

authRouter.post(
    '/2fa/buckup-code/regenerate',
    protect,
    RegenerateBuckupCodeLimiter,
    validate(RegenerateBuckupCodeSchema),
    regenerateBackupCode
);

// ----- Email Recovery Link Routes ------
authRouter.post(
    '/2fa/recovery/request',
    RequestRecoveryLinkLimiter,
    validate(EmailShcema),
    requestRecoveryLink
);

authRouter.post(
    '/2fa/recovery/verify',
    RequestRecoveryLinkLimiter,
    validate(VerifyRecoveryLinkSchema),
    verifyRecoveryLink
);

// ----- Me & Refresh Token Routes -----

authRouter.post(
    '/refresh',
    refreshToken
);

authRouter.get(
    '/me',
    protect,
    me
);

export default authRouter;