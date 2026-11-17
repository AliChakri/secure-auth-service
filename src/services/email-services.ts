import { Resend } from 'resend';
import { AppError } from '../utils/AppError.js';

const resend = new Resend(process.env.RESEND_API_KEY);

export const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Reusable helper to handle Resend logic and errors
 */
const sendEmail = async (to: string, subject: string, html: string) => {
  try {
    const { data, error } = await resend.emails.send({
      from: 'Auth System <onboarding@resend.dev>', // Use verified domain in production
      to,
      subject,
      html,
    });

    if (error) {
      console.error('📧 Resend Error:', error);
      throw new AppError(`Email failed: ${error.message}`, 500);
    }

    return data;
  } catch (err) {
    // If it's already an AppError, re-throw it; otherwise, wrap it
    if (err instanceof AppError) throw err;
    throw new AppError('Internal Email Service Error', 500);
  }
};

export const sendVerificationEmail = async (email: string, otp: string) => {
  const html = `
    <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee;">
      <h2 style="color: #333;">Verify Your Email</h2>
      <p>Your verification code is:</p>
      <h1 style="color: #4F46E5; letter-spacing: 5px; background: #f4f4f4; padding: 10px; display: inline-block;">
        ${otp}
      </h1>
      <p>This code will expire in 10 minutes.</p>
    </div>
  `;
  return await sendEmail(email, 'Verify Your Email', html);
};

export const sendPasswordResetEmail = async (email: string, otp: string) => {
  const html = `
    <div style="font-family: sans-serif; padding: 20px; border: 1px solid #eee;">
      <h2 style="color: #d32f2f;">Password Reset Request</h2>
      <p>Use the following code to reset your password:</p>
      <h1 style="color: #4F46E5; letter-spacing: 5px; background: #f4f4f4; padding: 10px; display: inline-block;">
        ${otp}
      </h1>
      <p>If you didn't request this, please secure your account.</p>
    </div>
  `;
  return await sendEmail(email, 'Password Reset Request', html);
};