"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeFile = exports.runVulnerabilityScan = void 0;
const fs_1 = __importDefault(require("fs"));
const nvdScanner_1 = require("../services/nvdScanner");
const fileScanner_1 = require("../services/fileScanner");
const auditService_1 = require("../services/auditService");
// ── Existing: Network Vulnerability Scan ──────────────────────────────────────
const runVulnerabilityScan = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const requestId = (0, auditService_1.getRequestId)(req);
    const actor = (0, auditService_1.getActorContext)(req);
    const { target, scanType } = req.body || {};
    try {
        if (!target) {
            yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'vulnerability_scan_rejected', category: 'security scan', status: 'denied', severity: 'low', source: 'vulnerability_scanner', requestId }, actor), { metadata: { reason: 'missing_target' }, errorCode: 'MISSING_TARGET' }));
            return res.status(400).json({ error: 'Target is required' });
        }
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'vulnerability_scan_requested', category: 'security scan', source: 'vulnerability_scanner', requestId }, actor), { resourceType: 'target', resourceId: (0, auditService_1.safeUrlPreview)(String(target)) || String(target), metadata: { scanType: scanType || 'Full CVE Scan' } }));
        const scanResult = yield (0, nvdScanner_1.performVulnerabilityScan)(target, scanType || 'Full CVE Scan');
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'vulnerability_scan_completed', category: 'security scan', source: 'vulnerability_scanner', requestId }, actor), { resourceType: 'target', resourceId: (0, auditService_1.safeUrlPreview)(String(target)) || String(target), metadata: { scanType: scanType || 'Full CVE Scan' } }));
        return res.status(200).json(scanResult);
    }
    catch (error) {
        console.error('Error in runVulnerabilityScan:', error);
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'vulnerability_scan_failed', category: 'security scan', status: 'failure', severity: 'high', source: 'vulnerability_scanner', requestId }, actor), { metadata: { reason: 'scan_execution_error' }, errorCode: 'SCAN_EXECUTION_ERROR' }));
        return res.status(500).json({ error: 'An error occurred during vulnerability scanning.' });
    }
});
exports.runVulnerabilityScan = runVulnerabilityScan;
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
const analyzeFile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    const uploadedFilePath = (_a = req.file) === null || _a === void 0 ? void 0 : _a.path;
    const requestId = (0, auditService_1.getRequestId)(req);
    const actor = (0, auditService_1.getActorContext)(req);
    try {
        // Guard: multer should have already rejected invalid uploads, but double-check
        if (!req.file || !uploadedFilePath) {
            yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'file_scan_rejected', category: 'security scan', status: 'denied', severity: 'low', source: 'file_scanner', requestId }, actor), { metadata: { reason: 'missing_file' }, errorCode: 'MISSING_FILE' }));
            res.status(400).json({
                error: 'No file uploaded. Please attach a file using the "file" field.',
            });
            return;
        }
        const { originalname, size } = req.file;
        console.log(`[FileScanner] Starting dual-engine scan for: ${originalname} (${size} bytes)`);
        // Run both engines concurrently and aggregate results
        const result = yield (0, fileScanner_1.scanFile)(uploadedFilePath, originalname, size);
        console.log(`[FileScanner] Scan complete — Status: ${result.status}, Findings: ${result.findings.length}`);
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'file_scan_completed', category: 'security scan', source: 'file_scanner', requestId }, actor), { resourceType: 'file', resourceId: originalname, severity: result.status === 'Malicious' ? 'critical' : result.status === 'Suspicious' ? 'medium' : 'low', metadata: { fileSize: size, scanStatus: result.status, findingCount: result.findings.length } }));
        res.status(200).json(result);
    }
    catch (error) {
        console.error('[FileScanner] Unhandled error during file analysis:', error);
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'file_scan_failed', category: 'security scan', status: 'failure', severity: 'high', source: 'file_scanner', requestId }, actor), { metadata: { fileName: (_b = req.file) === null || _b === void 0 ? void 0 : _b.originalname, reason: 'scan_execution_error' }, errorCode: 'SCAN_EXECUTION_ERROR' }));
        res.status(500).json({
            error: 'An internal error occurred during file analysis. The file has been securely deleted.',
        });
    }
    finally {
        // ── CRITICAL SECURITY CLEANUP ─────────────────────────────────────────
        // Delete the uploaded file unconditionally. This block runs whether the
        // scan succeeded, threw an error, or the response was already sent.
        if (uploadedFilePath) {
            try {
                if (fs_1.default.existsSync(uploadedFilePath)) {
                    fs_1.default.unlinkSync(uploadedFilePath);
                    console.log(`[FileScanner] Securely deleted temp file: ${uploadedFilePath}`);
                }
            }
            catch (cleanupErr) {
                console.error(`[FileScanner] CRITICAL: Failed to delete temp file ${uploadedFilePath}:`, cleanupErr.message);
            }
        }
    }
});
exports.analyzeFile = analyzeFile;
