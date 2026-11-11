import express from 'express';
import { runClientAudit, listAuditLogs, getAuditLogById } from '../controller/auditController';
import { verifyToken } from '../middleware/verifyToken';

const router = express.Router();

/**
 * GET /api/audits
 * Returns the application audit log stream with filters and summary stats.
 */
router.get('/', verifyToken, listAuditLogs);

/**
 * GET /api/audits/:id
 * Returns a single audit event.
 */
router.get('/:id', verifyToken, getAuditLogById);

/**
 * POST /api/audits/client
 *
 * Accepts a browser telemetry payload from the frontend,
 * resolves the client public IP, runs a port scan, and
 * returns a comprehensive AuditReport JSON.
 *
 * Protected: requires a valid JWT session.
 */
router.post('/client', verifyToken, runClientAudit);

export default router;
