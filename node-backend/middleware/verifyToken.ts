import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../util/jwt.util';

// Augment Express types for JWT payloads. `Request.user` is declared here
// explicitly (it was previously supplied implicitly by an undeclared
// @types/passport package in node_modules).
declare global {
  namespace Express {
    interface User {
      userId?: string;
      email?: string;
      role?: string;
    }
    interface Request {
      user?: User;
    }
  }
}

export type AuthenticatedRequest = Request;

/**
 * JWT Verification Middleware
 * Reads Access Token strictly from HttpOnly cookie (or Bearer Authorization header fallback)
 */
export const verifyToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // 1. Primary location: HttpOnly cookie
    let token = req.cookies?.accessToken;

    // 2. Fallback: Bearer Authorization header for headless API clients
    if (!token && req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required. No access token provided.',
        code: 'NO_TOKEN',
      });
    }

    // 3. Verify token signature and expiration
    const decoded = verifyAccessToken(token);
    req.user = decoded as Express.User;

    return next();
  } catch (error: any) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access token expired. Please refresh session.',
        code: 'TOKEN_EXPIRED',
      });
    }

    return res.status(401).json({
      error: 'Invalid access token.',
      code: 'TOKEN_INVALID',
    });
  }
};

/**
 * Optional JWT Verification Middleware
 * Attaches user payload if a valid token is present, but permits anonymous requests
 */
export const optionalVerifyToken = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    let token = req.cookies?.accessToken;
    if (!token && req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (token) {
      const decoded = verifyAccessToken(token);
      req.user = decoded as Express.User;
    }
  } catch {
    // Continue anonymously without blocking
  }
  return next();
};
