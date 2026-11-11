import rateLimit from 'express-rate-limit';

/**
 * Strict rate limiter for Authentication endpoints (Login, Register, Password Reset)
 * Mitigates credential stuffing, password brute-forcing, and email flooding.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes window
  max: 5, // Limit each IP to 5 sensitive auth attempts per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: {
    error: 'Too many authentication attempts. Please try again after 15 minutes.',
    code: 'RATE_LIMIT_EXCEEDED',
  },
  skipSuccessfulRequests: false,
});

/**
 * Moderate rate limiter for general API routes
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // 200 requests per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please slow down.',
    code: 'RATE_LIMIT_EXCEEDED',
  },
});

/**
 * Resend email verification limiter to prevent inbox harassment
 */
export const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Max 3 email trigger requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many email requests sent. Please try again later.',
    code: 'EMAIL_RATE_LIMIT_EXCEEDED',
  },
});
