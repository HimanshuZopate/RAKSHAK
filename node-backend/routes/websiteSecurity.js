"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const verifyToken_1 = require("../middleware/verifyToken");
const websiteSecurity_controller_1 = require("../controller/websiteSecurity.controller");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const websiteSecurityRouter = express_1.default.Router();
// Apply JWT authentication
websiteSecurityRouter.use(verifyToken_1.verifyToken);
/**
 * Rate limiter for website security scans
 * Restricts scans to 30 per 15 minutes to prevent network abuse
 */
const scanRateLimiter = (0, express_rate_limit_1.default)({
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
websiteSecurityRouter.post('/website-scan', websiteSecurity_controller_1.scanWebsiteHandler);
websiteSecurityRouter.post('/scan', websiteSecurity_controller_1.scanWebsiteHandler);
exports.default = websiteSecurityRouter;
