import jwt, { SignOptions } from 'jsonwebtoken';
import { Response, CookieOptions } from 'express';

export interface TokenUserPayload {
  userId: string;
  email: string;
  role: string;
}

export const getAccessTokenSecret = (): string =>
  process.env.ACCESS_TOKEN_SECRET || 'dev_fallback_access_secret_key_123456789!@#';
export const getRefreshTokenSecret = (): string =>
  process.env.REFRESH_TOKEN_SECRET || 'dev_fallback_refresh_secret_key_987654321!@#';

const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';

export const ACCESS_COOKIE_MAX_AGE = 15 * 60 * 1000; // 15 mins in ms
export const REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days in ms

/**
 * Standard secure cookie options conforming to OWASP guidelines
 */
export const getBaseCookieOptions = (): CookieOptions => {
  const isProduction = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true, // Prevents client-side script access (mitigating XSS theft)
    secure: isProduction, // Transmitted only via HTTPS in production
    sameSite: 'strict', // Strict CSRF defense
    path: '/',
  };
};

/**
 * Generate short-lived Access Token (15m default)
 */
export const generateAccessToken = (payload: TokenUserPayload): string => {
  const options: SignOptions = {
    expiresIn: (process.env.ACCESS_TOKEN_EXPIRY || ACCESS_TOKEN_EXPIRY) as SignOptions['expiresIn'],
  };
  return jwt.sign(payload, getAccessTokenSecret(), options);
};

/**
 * Generate long-lived Refresh Token (7d default)
 */
export const generateRefreshToken = (userId: string): string => {
  const options: SignOptions = {
    expiresIn: (process.env.REFRESH_TOKEN_EXPIRY || REFRESH_TOKEN_EXPIRY) as SignOptions['expiresIn'],
  };
  return jwt.sign({ userId }, getRefreshTokenSecret(), options);
};

/**
 * Verify Access Token
 */
export const verifyAccessToken = (token: string): TokenUserPayload => {
  return jwt.verify(token, getAccessTokenSecret()) as TokenUserPayload;
};

/**
 * Verify Refresh Token
 */
export const verifyRefreshToken = (token: string): { userId: string } => {
  return jwt.verify(token, getRefreshTokenSecret()) as { userId: string };
};

/**
 * Set HttpOnly, Secure, SameSite=Strict cookies on Express Response
 */
export const setAuthCookies = (
  res: Response,
  accessToken: string,
  refreshToken: string
): void => {
  const baseOptions = getBaseCookieOptions();

  res.cookie('accessToken', accessToken, {
    ...baseOptions,
    maxAge: ACCESS_COOKIE_MAX_AGE,
  });

  res.cookie('refreshToken', refreshToken, {
    ...baseOptions,
    maxAge: REFRESH_COOKIE_MAX_AGE,
  });
};

/**
 * Clear authentication cookies on logout or invalid session
 */
export const clearAuthCookies = (res: Response): void => {
  const baseOptions = getBaseCookieOptions();

  res.clearCookie('accessToken', baseOptions);
  res.clearCookie('refreshToken', baseOptions);
};
