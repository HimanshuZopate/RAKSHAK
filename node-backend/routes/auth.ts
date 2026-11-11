import express, { Request, Response, NextFunction } from 'express';
import {
  register,
  login,
  verifyEmail,
  resendVerificationEmail,
  refreshTokenController,
  logout,
  getCurrentUser,
  updateProfile,
} from '../controller/auth.controller';
import { forgotPassword, setNewPassword } from '../controller/user.controller';
import { verifyOtp } from '../controller/auth.controller';
import { authLimiter, emailLimiter } from '../middleware/rateLimiter';
import { verifyToken } from '../middleware/verifyToken';

const authRouter = express.Router();

// Status check
authRouter.get('/', (req: Request, res: Response) => {
  res.json({ status: 'Authentication service active', secure: true });
});

// 1. Local Authentication (Rate-limited to prevent brute forcing)
authRouter.post('/register', authLimiter, register);
authRouter.post('/login', authLimiter, login);
authRouter.post('/refresh', refreshTokenController);
authRouter.post('/logout', logout);

// 2. Email Verification Endpoints
authRouter.get('/verify-email', verifyEmail);
authRouter.post('/verify-email', verifyEmail);
authRouter.post('/resend-verification', emailLimiter, resendVerificationEmail);

// 3. User Identity Endpoint (Protected via verifyToken HttpOnly cookie)
authRouter.get('/me', verifyToken, getCurrentUser);
authRouter.patch('/profile', verifyToken, updateProfile);

// 4. Password Reset (Protected by rate limiter)
authRouter.post('/forgot', authLimiter, forgotPassword);
authRouter.post('/verify', authLimiter, verifyOtp);
authRouter.post('/newpassword', authLimiter, setNewPassword);
authRouter.post('/reset', authLimiter, forgotPassword);

export default authRouter;