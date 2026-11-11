import nodemailer from 'nodemailer';
import crypto from 'crypto';

export const generateSecureToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Configure Nodemailer transport with dev fallback
 */
const createTransporter = async () => {
  if (process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: Number(process.env.SMTP_PORT) || 587,
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  // Fallback to test ethereal account or console logger in development
  console.log('[EMAIL SERVICE] SMTP credentials not set. Creating test ethereal account / console fallback.');
  const testAccount = await nodemailer.createTestAccount().catch(() => null);
  if (testAccount) {
    return nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
  }

  return null;
};

/**
 * Send an email verification link
 */
export const sendVerificationEmail = async (
  to: string,
  token: string
): Promise<boolean> => {
  const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
  const verificationLink = `${clientUrl}/verify-email?token=${token}`;

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
      <h2 style="color: #1e293b; text-align: center;">Verify Your Account</h2>
      <p style="color: #475569; font-size: 16px;">
        Thank you for registering on <strong>Rakshak</strong>.
      </p>
      <p style="color: #475569; font-size: 16px;">
        To activate your account and adhere to our strict identity security policy, please verify your email address by clicking the button below:
      </p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="${verificationLink}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
          Verify Email Address
        </a>
      </div>
      <p style="color: #64748b; font-size: 14px;">
        Or copy and paste this link in your browser:<br/>
        <a href="${verificationLink}" style="color: #2563eb; word-break: break-all;">${verificationLink}</a>
      </p>
      <p style="color: #94a3b8; font-size: 12px; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 10px;">
        This link will expire in 24 hours. If you did not sign up for this account, please disregard this email.
      </p>
    </div>
  `;

  try {
    const transporter = await createTransporter();
    if (!transporter) {
      console.log(`\n======================================================`);
      console.log(`[EMAIL SIMULATION] Verification email for: ${to}`);
      console.log(`Verification URL: ${verificationLink}`);
      console.log(`======================================================\n`);
      return true;
    }

    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM || '"Security System" <noreply@security.local>',
      to,
      subject: 'Verify your Security Dashboard Account',
      html: htmlContent,
    });

    console.log(`[EMAIL SENT] Verification email delivered to ${to}. MessageId: ${info.messageId}`);
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) {
      console.log(`[EMAIL PREVIEW] Ethereal preview: ${previewUrl}`);
    }
    return true;
  } catch (error) {
    console.error('[EMAIL ERROR] Failed to send verification email:', error);
    console.log(`[DEV FALLBACK] Direct Verification Link for testing: ${verificationLink}`);
    return false;
  }
};
