import multer, { FileFilterCallback } from 'multer';
import { Request } from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { v4 as uuidv4 } from 'uuid';

// ── Secure Temporary Upload Directory ──────────────────────────────────────────
// Use OS temp dir to ensure files land outside the web root.
const UPLOAD_DIR = path.join(
  process.env.TEMP_UPLOAD_DIR || os.tmpdir(),
  'security-scans'
);

// Create directory if it does not exist
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ── Allowed MIME Types ─────────────────────────────────────────────────────────
const ALLOWED_MIMETYPES = new Set([
  // Microsoft Office
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  // PDF
  'application/pdf',
  // Plain text / Code
  'text/plain',
  'text/html',
  'text/css',
  'text/javascript',
  'application/javascript',
  'application/json',
  'application/xml',
  'text/xml',
  'text/x-python',
  'text/x-java-source',
  'text/x-c',
  'text/x-c++src',
  'text/x-php',
  'text/x-ruby',
  'text/x-shellscript',
  'application/x-sh',
]);

// ── Allowed Extensions (Secondary Guard) ──────────────────────────────────────
const ALLOWED_EXTENSIONS = new Set([
  '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.pdf',
  '.txt', '.html', '.css', '.js', '.ts', '.jsx', '.tsx',
  '.json', '.xml', '.yml', '.yaml',
  '.py', '.java', '.c', '.cpp', '.h', '.cs', '.go',
  '.rb', '.php', '.sh', '.bash', '.ps1', '.md',
]);

// ── Disk Storage Configuration ─────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  /**
   * Generate a UUID-based filename to prevent:
   *  - Path traversal via malicious filenames
   *  - Overwriting existing files
   *  - Executable file leakage (no extension mapping to shell)
   */
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeFilename = `scan-${uuidv4()}${ext}`;
    cb(null, safeFilename);
  },
});

// ── MIME Type + Extension File Filter ─────────────────────────────────────────
const fileFilter = (
  _req: Request,
  file: Express.Multer.File,
  cb: FileFilterCallback
): void => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mimeAllowed = ALLOWED_MIMETYPES.has(file.mimetype);
  const extAllowed = ALLOWED_EXTENSIONS.has(ext);

  if (mimeAllowed && extAllowed) {
    cb(null, true);
  } else {
    cb(
      new Error(
        `File type not permitted. Allowed: documents, PDFs, text, and code files. Received MIME: ${file.mimetype}`
      )
    );
  }
};

// ── Export Configured Multer Instance ─────────────────────────────────────────
export const uploadFile = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 15 * 1024 * 1024, // 15 MB hard limit
    files: 1,                    // Single file per request
  },
});

export { UPLOAD_DIR };
