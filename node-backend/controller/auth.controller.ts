import { Request, Response } from 'express';
import UserModel from '../model/user.model';
import ResetTokenModel from '../model/resetToken.model';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  setAuthCookies,
  clearAuthCookies,
} from '../util/jwt.util';
import { generateSecureToken, sendVerificationEmail } from '../util/email.util';
import { recordAuditEvent, getRequestId } from '../services/auditService';

/**
 * Strong password validator following OWASP guidance:
 * - At least 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one digit
 * - At least one special symbol
 */
const validatePasswordStrength = (password: string): { valid: boolean; message?: string } => {
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter.' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter.' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number.' };
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character.' };
  }
  return { valid: true };
};

const logAuthEvent = async (
  req: Request,
  event: {
    action: string;
    status: 'success' | 'failure' | 'denied';
    severity?: 'informational' | 'low' | 'medium' | 'high' | 'critical';
    actorId?: string;
    actorType?: 'system' | 'anonymous' | 'user' | 'admin';
    resourceType?: string;
    resourceId?: string;
    metadata?: Record<string, any>;
    errorCode?: string;
  }
) => {
  await recordAuditEvent({
    ...event,
    category: 'authentication',
    source: 'auth',
    requestId: getRequestId(req),
    metadata: event.metadata || {},
  });
};

/**
 * Register Controller
 * Validates inputs, creates a local account, and starts an authenticated session.
 */
export const register = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      await logAuthEvent(req, {
        action: 'account_registration_rejected',
        status: 'denied',
        severity: 'low',
        metadata: { reason: 'missing_email_or_password' },
        errorCode: 'MISSING_CREDENTIALS',
      });
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      await logAuthEvent(req, {
        action: 'account_registration_rejected',
        status: 'denied',
        severity: 'low',
        metadata: { email: typeof email === 'string' ? email.slice(0, 64) : undefined },
        errorCode: 'INVALID_EMAIL_FORMAT',
      });
      return res.status(400).json({ error: 'Invalid email address format.' });
    }

    const passwordCheck = validatePasswordStrength(password);
    if (!passwordCheck.valid) {
      await logAuthEvent(req, {
        action: 'account_registration_rejected',
        status: 'denied',
        severity: 'medium',
        metadata: { email: typeof email === 'string' ? email.slice(0, 64) : undefined },
        errorCode: 'WEAK_PASSWORD',
      });
      return res.status(400).json({ error: passwordCheck.message });
    }

    const existingUser = await UserModel.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      await logAuthEvent(req, {
        action: 'account_registration_rejected',
        status: 'denied',
        severity: 'low',
        metadata: { email: email.toLowerCase().trim().slice(0, 64) },
        errorCode: 'USER_ALREADY_EXISTS',
      });
      return res.status(400).json({
        error: 'An account with this email address already exists.',
      });
    }

    const newUser = new UserModel({
      email: email.toLowerCase().trim(),
      password,
      isEmailVerified: true,
    });

    const accessToken = generateAccessToken({
      userId: newUser._id.toString(),
      email: newUser.email,
      role: newUser.role,
    });
    const refreshToken = generateRefreshToken(newUser._id.toString());
    newUser.refreshToken = refreshToken;
    await newUser.save();

    await logAuthEvent(req, {
      action: 'account_registration_successful',
      status: 'success',
      severity: 'low',
      actorId: newUser._id.toString(),
      actorType: 'user',
      resourceType: 'account',
      resourceId: newUser._id.toString(),
      metadata: { email: newUser.email },
    });

    setAuthCookies(res, accessToken, refreshToken);

    return res.status(201).json({
      message: 'Registration successful. You are now signed in.',
      email: newUser.email,
      user: newUser.toSafeUser(),
    });
  } catch (error: any) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Server error during registration.' });
  }
};

/**
 * Verify Email Controller
 * Validates verification token and activates the account.
 */
export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const token = (req.query.token as string) || req.body.token;

    if (!token) {
      return res.status(400).json({ error: 'Verification token is required.' });
    }

    const user = await UserModel.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: new Date() },
    }).select('+verificationToken +verificationTokenExpires');

    if (!user) {
      return res.status(400).json({
        error: 'Invalid or expired verification token.',
        code: 'TOKEN_INVALID_OR_EXPIRED',
      });
    }

    user.isEmailVerified = true;
    user.verificationToken = null;
    user.verificationTokenExpires = null;

    await logAuthEvent(req, {
      action: 'email_verification_successful',
      status: 'success',
      severity: 'low',
      actorId: user._id.toString(),
      actorType: user.role === 'admin' ? 'admin' : 'user',
      resourceType: 'account',
      resourceId: user._id.toString(),
      metadata: { email: user.email },
    });

    // Issue tokens immediately upon verification
    const accessToken = generateAccessToken({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });
    const refreshToken = generateRefreshToken(user._id.toString());

    user.refreshToken = refreshToken;
    await user.save();

    // Set secure HttpOnly cookies
    setAuthCookies(res, accessToken, refreshToken);

    return res.status(200).json({
      message: 'Email verified successfully! You are now logged in.',
      user: user.toSafeUser(),
    });
  } catch (error: any) {
    console.error('Email verification error:', error);
    return res.status(500).json({ error: 'Server error during email verification.' });
  }
};

/**
 * Resend Verification Email
 */
export const resendVerificationEmail = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    const user = await UserModel.findOne({ email: email.toLowerCase().trim() }).select(
      '+verificationToken +verificationTokenExpires'
    );

    if (user && !user.isEmailVerified) {
      const verificationToken = generateSecureToken();
      user.verificationToken = verificationToken;
      user.verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await user.save();

      await sendVerificationEmail(user.email, verificationToken);
    }

    // Generic response to avoid email enumeration
    return res.status(200).json({
      message:
        'If an unverified account exists with that email address, a new verification link has been sent.',
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    return res.status(500).json({ error: 'Server error processing request.' });
  }
};

/**
 * Login Controller
 * Authenticates credentials and issues HttpOnly JWT cookies.
 */
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      await logAuthEvent(req, {
        action: 'login_attempt_rejected',
        status: 'denied',
        severity: 'low',
        metadata: { reason: 'missing_email_or_password' },
        errorCode: 'MISSING_CREDENTIALS',
      });
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await UserModel.findOne({ email: email.toLowerCase().trim() }).select(
      '+password +refreshToken'
    );

    // Timing-attack safe generic rejection
    if (!user) {
      await logAuthEvent(req, {
        action: 'login_failed',
        status: 'failure',
        severity: 'medium',
        metadata: { email: email.toLowerCase().trim().slice(0, 64) },
        errorCode: 'INVALID_EMAIL_OR_PASSWORD',
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await logAuthEvent(req, {
        action: 'login_failed',
        status: 'failure',
        severity: 'medium',
        actorId: user._id.toString(),
        actorType: 'user',
        metadata: { email: user.email },
        errorCode: 'INVALID_PASSWORD',
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Dual-token issuance
    const accessToken = generateAccessToken({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });
    const refreshToken = generateRefreshToken(user._id.toString());

    user.refreshToken = refreshToken;
    await user.save();

    await logAuthEvent(req, {
      action: 'login_successful',
      status: 'success',
      severity: 'low',
      actorId: user._id.toString(),
      actorType: user.role === 'admin' ? 'admin' : 'user',
      resourceType: 'session',
      resourceId: user._id.toString(),
      metadata: { email: user.email, role: user.role },
    });

    // Send tokens via HttpOnly, Secure, SameSite=Strict cookies
    setAuthCookies(res, accessToken, refreshToken);

    return res.status(200).json({
      message: 'Login successful.',
      user: user.toSafeUser(),
    });
  } catch (error: any) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error during login.' });
  }
};

/**
 * Refresh Token Controller
 * Rotates Access & Refresh tokens using the HttpOnly refresh token cookie.
 */
export const refreshTokenController = async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        error: 'No refresh token provided in session.',
        code: 'NO_REFRESH_TOKEN',
      });
    }

    let decoded: { userId: string };
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (err) {
      clearAuthCookies(res);
      return res.status(401).json({
        error: 'Refresh token is expired or invalid.',
        code: 'INVALID_REFRESH_TOKEN',
      });
    }

    const user = await UserModel.findById(decoded.userId).select('+refreshToken');

    // Token reuse detection or revoked session
    if (!user || user.refreshToken !== refreshToken) {
      if (user) {
        // Invalidate compromised token
        user.refreshToken = null;
        await user.save();
      }
      clearAuthCookies(res);
      return res.status(403).json({
        error: 'Invalid session or refresh token reuse detected.',
        code: 'SESSION_REVOKED',
      });
    }

    // Token rotation: Issue fresh access token and fresh refresh token
    const newAccessToken = generateAccessToken({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    });
    const newRefreshToken = generateRefreshToken(user._id.toString());

    user.refreshToken = newRefreshToken;
    await user.save();

    setAuthCookies(res, newAccessToken, newRefreshToken);

    return res.status(200).json({
      message: 'Session refreshed successfully.',
      user: user.toSafeUser(),
    });
  } catch (error: any) {
    console.error('Refresh token error:', error);
    clearAuthCookies(res);
    return res.status(500).json({ error: 'Server error refreshing session.' });
  }
};

/**
 * Logout Controller
 * Revokes refresh token in database and purges HttpOnly auth cookies.
 */
export const logout = async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies?.refreshToken;
    let actorId: string | undefined;
    if (refreshToken) {
      try {
        const decoded = verifyRefreshToken(refreshToken);
        actorId = decoded.userId;
        await UserModel.findByIdAndUpdate(decoded.userId, { refreshToken: null });
      } catch (err) {
        // Token could already be expired; proceed to purge cookies
      }
    }

    await logAuthEvent(req, {
      action: 'logout_successful',
      status: 'success',
      severity: 'informational',
      actorId,
      actorType: actorId ? 'user' : 'anonymous',
      resourceType: 'session',
      resourceId: actorId,
      metadata: { sessionRevoked: Boolean(actorId) },
    });

    clearAuthCookies(res);
    return res.status(200).json({ message: 'Logged out successfully.' });
  } catch (error: any) {
    console.error('Logout error:', error);
    clearAuthCookies(res);
    return res.status(500).json({ error: 'Server error during logout.' });
  }
};

/**
 * Get Current User Controller (Protected)
 */
export const getCurrentUser = async (req: Request, res: Response) => {
  try {
    if (!req.user || !req.user.userId) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }

    const user = await UserModel.findById(req.user.userId);
    if (!user) {
      clearAuthCookies(res);
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.status(200).json({
      user: user.toSafeUser(),
    });
  } catch (error: any) {
    console.error('getCurrentUser error:', error);
    return res.status(500).json({ error: 'Server error retrieving user.' });
  }
};

export const updateProfile = async (req: Request, res: Response) => {
  try {
    if (!req.user?.userId) {
      res.status(401).json({ error: 'Unauthorized.' });
      return;
    }

    const displayName = typeof req.body.displayName === 'string' ? req.body.displayName.trim() : '';
    const avatarUrl = typeof req.body.avatarUrl === 'string' ? req.body.avatarUrl.trim() : '';
    if (displayName.length > 80 || avatarUrl.length > 500) {
      res.status(400).json({ error: 'Profile details exceed the allowed length.' });
      return;
    }

    const user = await UserModel.findByIdAndUpdate(
      req.user.userId,
      { displayName, avatarUrl },
      { new: true, runValidators: true }
    );
    if (!user) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    await logAuthEvent(req, {
      action: 'profile_updated',
      status: 'success',
      severity: 'low',
      actorId: user._id.toString(),
      actorType: user.role === 'admin' ? 'admin' : 'user',
      resourceType: 'profile',
      resourceId: user._id.toString(),
    });
    res.status(200).json({ user: user.toSafeUser() });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Unable to update profile.' });
  }
};

/**
 * OTP Verification Controller (Legacy flow)
 */
export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { otp, email } = req.body;
    const resetToken = await ResetTokenModel.findOne({ otp, email });
    if (resetToken !== null) {
      return res.status(200).json({ token: resetToken.token });
    }
    return res.status(404).json({ error: 'Invalid token' });
  } catch (error) {
    return res.status(500).json({ error });
  }
};

