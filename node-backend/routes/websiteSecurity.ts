import express from 'express';
import { verifyToken } from '../middleware/verifyToken';
import { scanWebsiteHandler } from '../controller/websiteSecurity.controller';
import rateLimit from 'express-rate-limit';

const websiteSecurityRouter = express.Router();

// Apply JWT authentication
websiteSecurityRouter.use(verifyToken);

/**
 * Rate limiter for website security scans
 * Restricts scans to 30 per 15 minutes to prevent network abuse
 */
const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many website scan requests. Please wait a few minutes before scanning again.',
    code: 'SCAN_RATE_LIMIT_EXCEEDED',
  },
});

websiteSecurityRouter.use(scanRateLimiter);

/**
 * POST /api/security/website-scan
 * Also supports /api/website-security/scan and /website-scan
 */
websiteSecurityRouter.post('/website-scan', scanWebsiteHandler);
websiteSecurityRouter.post('/scan', scanWebsiteHandler);

export default websiteSecurityRouter;
