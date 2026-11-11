import express from 'express';
import { runVulnerabilityScan, analyzeFile } from '../controller/scanners';
import { uploadFile } from '../middleware/fileUpload';

const router = express.Router();

// Existing: Network vulnerability scan
router.post('/vulnerability', runVulnerabilityScan);

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
