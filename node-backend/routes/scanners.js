"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const express_rate_limit_1 = __importStar(require("express-rate-limit"));
const scanners_1 = require("../controller/scanners");
const vulnScan_controller_1 = require("../controller/vulnScan.controller");
const fileUpload_1 = require("../middleware/fileUpload");
const verifyToken_1 = require("../middleware/verifyToken");
const router = express_1.default.Router();
// Legacy CVE keyword lookup (kept for API compatibility; the UI now uses /web-scans).
router.post('/vulnerability', scanners_1.runVulnerabilityScan);
// ── Web vulnerability assessment (authenticated, per-user) ──────────────────
const perUserKey = (req) => { var _a; return (((_a = req.user) === null || _a === void 0 ? void 0 : _a.userId) ? `user:${req.user.userId}` : (0, express_rate_limit_1.ipKeyGenerator)(req.ip || '')); };
const scanStartLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: perUserKey,
    message: { success: false, code: 'RATE_LIMIT_EXCEEDED', error: 'Too many scans started. Please wait a few minutes.' },
});
const scanReadLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: perUserKey,
    message: { success: false, code: 'RATE_LIMIT_EXCEEDED', error: 'Too many requests. Please slow down.' },
});
router.get('/web-scans/profiles', verifyToken_1.verifyToken, vulnScan_controller_1.getScanProfiles);
router.get('/web-scans', verifyToken_1.verifyToken, scanReadLimiter, vulnScan_controller_1.listWebScans);
router.post('/web-scans', verifyToken_1.verifyToken, scanStartLimiter, vulnScan_controller_1.startWebScan);
router.get('/web-scans/:id', verifyToken_1.verifyToken, scanReadLimiter, vulnScan_controller_1.getWebScan);
router.post('/web-scans/:id/cancel', verifyToken_1.verifyToken, scanReadLimiter, vulnScan_controller_1.cancelWebScan);
/**
 * POST /api/scanners/analyze-file
 * Accepts a single file upload and runs dual-engine malware + static analysis.
 * Multer middleware handles multipart parsing, size limits, and MIME filtering.
 */
router.post('/analyze-file', (req, res, next) => {
    // Run multer as middleware, converting multer errors to a clean JSON response
    fileUpload_1.uploadFile.single('file')(req, res, (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({
                    error: 'File too large. Maximum allowed size is 15MB.',
                });
            }
            return res.status(400).json({
                error: err.message || 'File upload rejected.',
            });
        }
        next();
    });
}, scanners_1.analyzeFile);
exports.default = router;
