"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const scanners_1 = require("../controller/scanners");
const fileUpload_1 = require("../middleware/fileUpload");
const router = express_1.default.Router();
// Existing: Network vulnerability scan
router.post('/vulnerability', scanners_1.runVulnerabilityScan);
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
