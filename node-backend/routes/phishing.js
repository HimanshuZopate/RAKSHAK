"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const verifyToken_1 = require("../middleware/verifyToken");
const phishing_controller_1 = require("../controller/phishing.controller");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const phishingRouter = express_1.default.Router();
// Apply authentication middleware
phishingRouter.use(verifyToken_1.verifyToken);
/**
 * Rate limiter specifically for phishing analysis endpoints
 * Prevents abuse while allowing legitimate usage
 */
const phishingLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 60,
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
phishingRouter.post('/analyze-url', phishing_controller_1.analyzeUrlHandler);
/**
 * POST /api/phishing/analyze-message
 * Analyze suspicious message/email/SMS content
 * Body: { message: string, senderInfo?: string, analysisType?: 'message' | 'email_sms' }
 */
phishingRouter.post('/analyze-message', phishing_controller_1.analyzeMessageHandler);
exports.default = phishingRouter;
