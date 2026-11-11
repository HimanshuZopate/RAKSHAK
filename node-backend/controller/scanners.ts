import { Request, Response } from 'express';
import fs from 'fs';
import { performVulnerabilityScan } from '../services/nvdScanner';
import { scanFile } from '../services/fileScanner';
import { getActorContext, getRequestId, recordAuditEvent, safeUrlPreview } from '../services/auditService';

// ── Existing: Network Vulnerability Scan ──────────────────────────────────────
export const runVulnerabilityScan = async (req: Request, res: Response) => {
    const requestId = getRequestId(req);
    const actor = getActorContext(req);
    const { target, scanType } = req.body || {};

    try {
        if (!target) {
            await recordAuditEvent({
                action: 'vulnerability_scan_rejected',
                category: 'security scan',
                status: 'denied',
                severity: 'low',
                source: 'vulnerability_scanner',
                requestId,
                ...actor,
                metadata: { reason: 'missing_target' },
                errorCode: 'MISSING_TARGET',
            });
            return res.status(400).json({ error: 'Target is required' });
        }

        await recordAuditEvent({
            action: 'vulnerability_scan_requested',
            category: 'security scan',
            source: 'vulnerability_scanner',
            requestId,
            ...actor,
            resourceType: 'target',
            resourceId: safeUrlPreview(String(target)) || String(target),
            metadata: { scanType: scanType || 'Full CVE Scan' },
        });

        const scanResult = await performVulnerabilityScan(target, scanType || 'Full CVE Scan');

        await recordAuditEvent({
            action: 'vulnerability_scan_completed',
            category: 'security scan',
            source: 'vulnerability_scanner',
            requestId,
            ...actor,
            resourceType: 'target',
            resourceId: safeUrlPreview(String(target)) || String(target),
            metadata: { scanType: scanType || 'Full CVE Scan' },
        });

        return res.status(200).json(scanResult);
    } catch (error: any) {
        console.error('Error in runVulnerabilityScan:', error);
        await recordAuditEvent({
            action: 'vulnerability_scan_failed',
            category: 'security scan',
            status: 'failure',
            severity: 'high',
            source: 'vulnerability_scanner',
            requestId,
            ...actor,
            metadata: { reason: 'scan_execution_error' },
            errorCode: 'SCAN_EXECUTION_ERROR',
        });
        return res.status(500).json({ error: 'An error occurred during vulnerability scanning.' });
    }
};

// ── New: File Malware & Vulnerability Analysis ────────────────────────────────
/**
 * POST /api/scanners/analyze-file
 *
 * Accepts a multipart/form-data upload with a single `file` field.
 * Runs ClamAV signature scan + static regex analysis concurrently.
 *
 * SECURITY GUARANTEE: The uploaded file is ALWAYS deleted in the finally
 * block — even if scanning throws an unhandled exception — ensuring zero
 * file retention on the server disk.
 */
export const analyzeFile = async (req: Request, res: Response): Promise<void> => {
  const uploadedFilePath = req.file?.path;
  const requestId = getRequestId(req);
  const actor = getActorContext(req);

  try {
    // Guard: multer should have already rejected invalid uploads, but double-check
    if (!req.file || !uploadedFilePath) {
      await recordAuditEvent({
        action: 'file_scan_rejected',
        category: 'security scan',
        status: 'denied',
        severity: 'low',
        source: 'file_scanner',
        requestId,
        ...actor,
        metadata: { reason: 'missing_file' },
        errorCode: 'MISSING_FILE',
      });
      res.status(400).json({
        error: 'No file uploaded. Please attach a file using the "file" field.',
      });
      return;
    }

    const { originalname, size } = req.file;

    console.log(`[FileScanner] Starting dual-engine scan for: ${originalname} (${size} bytes)`);

    // Run both engines concurrently and aggregate results
    const result = await scanFile(uploadedFilePath, originalname, size);

    console.log(`[FileScanner] Scan complete — Status: ${result.status}, Findings: ${result.findings.length}`);
    await recordAuditEvent({
      action: 'file_scan_completed',
      category: 'security scan',
      source: 'file_scanner',
      requestId,
      ...actor,
      resourceType: 'file',
      resourceId: originalname,
      severity: result.status === 'Malicious' ? 'critical' : result.status === 'Suspicious' ? 'medium' : 'low',
      metadata: { fileSize: size, scanStatus: result.status, findingCount: result.findings.length },
    });

    res.status(200).json(result);
  } catch (error: any) {
    console.error('[FileScanner] Unhandled error during file analysis:', error);
    await recordAuditEvent({
      action: 'file_scan_failed',
      category: 'security scan',
      status: 'failure',
      severity: 'high',
      source: 'file_scanner',
      requestId,
      ...actor,
      metadata: { fileName: req.file?.originalname, reason: 'scan_execution_error' },
      errorCode: 'SCAN_EXECUTION_ERROR',
    });
    res.status(500).json({
      error: 'An internal error occurred during file analysis. The file has been securely deleted.',
    });
  } finally {
    // ── CRITICAL SECURITY CLEANUP ─────────────────────────────────────────
    // Delete the uploaded file unconditionally. This block runs whether the
    // scan succeeded, threw an error, or the response was already sent.
    if (uploadedFilePath) {
      try {
        if (fs.existsSync(uploadedFilePath)) {
          fs.unlinkSync(uploadedFilePath);
          console.log(`[FileScanner] Securely deleted temp file: ${uploadedFilePath}`);
        }
      } catch (cleanupErr: any) {
        console.error(`[FileScanner] CRITICAL: Failed to delete temp file ${uploadedFilePath}:`, cleanupErr.message);
      }
    }
  }
};
