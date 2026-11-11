"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const auditController_1 = require("../controller/auditController");
const verifyToken_1 = require("../middleware/verifyToken");
const router = express_1.default.Router();
/**
 * GET /api/audits
 * Returns the application audit log stream with filters and summary stats.
 */
router.get('/', verifyToken_1.verifyToken, auditController_1.listAuditLogs);
/**
 * GET /api/audits/:id
 * Returns a single audit event.
 */
router.get('/:id', verifyToken_1.verifyToken, auditController_1.getAuditLogById);
/**
 * POST /api/audits/client
 *
 * Accepts a browser telemetry payload from the frontend,
 * resolves the client public IP, runs a port scan, and
 * returns a comprehensive AuditReport JSON.
 *
 * Protected: requires a valid JWT session.
 */
router.post('/client', verifyToken_1.verifyToken, auditController_1.runClientAudit);
exports.default = router;
