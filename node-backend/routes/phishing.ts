import express from 'express';
import { verifyToken } from '../middleware/verifyToken';
import { analyzeUrlHandler, analyzeMessageHandler } from '../controller/phishing.controller';
import rateLimit from 'express-rate-limit';

const phishingRouter = express.Router();

// Apply authentication middleware
phishingRouter.use(verifyToken);

/**
 * Rate limiter specifically for phishing analysis endpoints
 * Prevents abuse while allowing legitimate usage
 */
const phishingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60, // 60 analyses per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many analysis requests. Please try again later.',
    code: 'PHISHING_RATE_LIMIT_EXCEEDED',
  },
});

phishingRouter.use(phishingLimiter);

/**
 * POST /api/phishing/analyze-url
 * Analyze a suspicious URL for phishing indicators
 * Body: { url: string }
 */
phishingRouter.post('/analyze-url', analyzeUrlHandler);

/**
 * POST /api/phishing/analyze-message
 * Analyze suspicious message/email/SMS content
 * Body: { message: string, senderInfo?: string, analysisType?: 'message' | 'email_sms' }
 */
phishingRouter.post('/analyze-message', analyzeMessageHandler);

export default phishingRouter;
