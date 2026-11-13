import express from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { runVulnerabilityScan, analyzeFile } from '../controller/scanners';
import { cancelWebScan, getScanProfiles, getWebScan, listWebScans, startWebScan } from '../controller/vulnScan.controller';
import { uploadFile } from '../middleware/fileUpload';
import { verifyToken } from '../middleware/verifyToken';

const router = express.Router();

// Legacy CVE keyword lookup (kept for API compatibility; the UI now uses /web-scans).
router.post('/vulnerability', runVulnerabilityScan);

// ── Web vulnerability assessment (authenticated, per-user) ──────────────────
const perUserKey = (req: express.Request) => (req.user?.userId ? `user:${req.user.userId}` : ipKeyGenerator(req.ip || ''));
const scanStartLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: perUserKey,
  message: { success: false, code: 'RATE_LIMIT_EXCEEDED', error: 'Too many scans started. Please wait a few minutes.' },
});
const scanReadLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: perUserKey,
  message: { success: false, code: 'RATE_LIMIT_EXCEEDED', error: 'Too many requests. Please slow down.' },
});

router.get('/web-scans/profiles', verifyToken, getScanProfiles);
router.get('/web-scans', verifyToken, scanReadLimiter, listWebScans);
router.post('/web-scans', verifyToken, scanStartLimiter, startWebScan);
router.get('/web-scans/:id', verifyToken, scanReadLimiter, getWebScan);
router.post('/web-scans/:id/cancel', verifyToken, scanReadLimiter, cancelWebScan);

/**
 * POST /api/scanners/analyze-file
 * Accepts a single file upload and runs dual-engine malware + static analysis.
 * Multer middleware handles multipart parsing, size limits, and MIME filtering.
 */
router.post(
  '/analyze-file',
  (req, res, next) => {
    // Run multer as middleware, converting multer errors to a clean JSON response
    uploadFile.single('file')(req, res, (err: any) => {
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
  },
  analyzeFile
);

export default router;
