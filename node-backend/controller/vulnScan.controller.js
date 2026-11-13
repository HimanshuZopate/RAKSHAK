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
exports.cancelWebScan = exports.getWebScan = exports.listWebScans = exports.startWebScan = exports.getScanProfiles = void 0;
const mongoose_1 = __importDefault(require("mongoose"));
const scanReport_model_1 = require("../model/scanReport.model");
const serviceSocket_1 = require("../socket/serviceSocket");
const auditService_1 = require("../services/auditService");
const orchestrator_1 = require("../services/vulnScanner/orchestrator");
const PROFILES = ['quick', 'standard', 'comprehensive'];
const fail = (res, status, code, error) => res.status(status).json({ success: false, code, error });
const userIdOf = (req) => { var _a; return (((_a = req.user) === null || _a === void 0 ? void 0 : _a.userId) ? String(req.user.userId) : null); };
/** Public API shape of a stored web scan (never includes legacy/internal fields). */
const toApi = (doc, includeDetails) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
    return (Object.assign({ id: doc._id.toString(), targetUrl: doc.targetUrl, targetHost: doc.targetHost, profile: doc.profile, scanStatus: doc.scanStatus, startedAt: doc.startedAt, completedAt: (_a = doc.completedAt) !== null && _a !== void 0 ? _a : null, durationMs: (_b = doc.durationMs) !== null && _b !== void 0 ? _b : null, requestCount: (_c = doc.requestCount) !== null && _c !== void 0 ? _c : null, scannerVersion: doc.scannerVersion, summary: (_d = doc.summary) !== null && _d !== void 0 ? _d : null, errorMessage: (_e = doc.errorMessage) !== null && _e !== void 0 ? _e : null }, (includeDetails
        ? {
            findings: (_f = doc.webFindings) !== null && _f !== void 0 ? _f : [],
            checks: (_g = doc.checks) !== null && _g !== void 0 ? _g : [],
            technologies: (_h = doc.technologies) !== null && _h !== void 0 ? _h : [],
            tls: (_j = doc.tls) !== null && _j !== void 0 ? _j : null,
            headerSnapshot: (_k = doc.headerSnapshot) !== null && _k !== void 0 ? _k : null,
            limitations: (_l = doc.limitations) !== null && _l !== void 0 ? _l : [],
            live: doc.scanStatus === 'running' ? (0, orchestrator_1.getLiveProgress)(doc._id.toString()) : null,
        }
        : {})));
};
/** GET /api/scanners/web-scans/profiles — describes what each profile really runs. */
const getScanProfiles = (_req, res) => {
    res.json({
        success: true,
        profiles: PROFILES.map((profile) => ({
            id: profile,
            checks: (0, orchestrator_1.checksForProfile)(profile).map((c) => ({ id: c.id, label: c.label, phase: c.phase })),
            maxDurationSeconds: orchestrator_1.PROFILE_LIMITS[profile].maxDurationMs / 1000,
            maxRequests: orchestrator_1.PROFILE_LIMITS[profile].maxRequests,
        })),
    });
};
exports.getScanProfiles = getScanProfiles;
/** POST /api/scanners/web-scans  { url, profile, authorizationConfirmed: true } */
const startWebScan = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const userId = userIdOf(req);
    if (!userId)
        return fail(res, 401, 'AUTH_REQUIRED', 'Please sign in to run a scan.');
    const { url, profile, authorizationConfirmed } = req.body || {};
    if (authorizationConfirmed !== true) {
        return fail(res, 400, 'AUTHORIZATION_REQUIRED', 'Confirm that you own the target or are explicitly authorised to test it.');
    }
    if (typeof profile !== 'string' || !PROFILES.includes(profile)) {
        return fail(res, 400, 'INVALID_PROFILE', `profile must be one of: ${PROFILES.join(', ')}.`);
    }
    if (typeof url !== 'string' || !url.trim())
        return fail(res, 400, 'INVALID_URL', 'A target URL is required.');
    try {
        const { scanId, snapshot } = yield (0, orchestrator_1.startScan)({ userId, url, profile: profile, emit: serviceSocket_1.emitToUser });
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, (0, auditService_1.getActorContext)(req)), { action: 'web_vulnerability_scan_started', category: 'security scan', source: 'vulnerability_scanner', requestId: (0, auditService_1.getRequestId)(req), resourceType: 'target', resourceId: snapshot.target.slice(0, 200), metadata: { profile, scanId, authorizationConfirmed: true } }));
        return res.status(202).json({ success: true, scan: snapshot });
    }
    catch (err) {
        if (err instanceof orchestrator_1.ScanRequestError) {
            if (err.code === 'TARGET_REJECTED') {
                yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, (0, auditService_1.getActorContext)(req)), { action: 'web_vulnerability_scan_rejected', category: 'security scan', status: 'denied', severity: 'low', source: 'vulnerability_scanner', requestId: (0, auditService_1.getRequestId)(req), errorCode: err.code, metadata: { reason: err.message.slice(0, 200) } }));
            }
            return fail(res, err.status, err.code, err.message);
        }
        console.error('[VulnScan] start failed:', err === null || err === void 0 ? void 0 : err.message);
        return fail(res, 500, 'SCAN_START_FAILED', 'The scan could not be started.');
    }
});
exports.startWebScan = startWebScan;
/** GET /api/scanners/web-scans?limit=20 — current user's scan history (summaries only). */
const listWebScans = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const userId = userIdOf(req);
    if (!userId)
        return fail(res, 401, 'AUTH_REQUIRED', 'Please sign in.');
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 50);
    try {
        const docs = yield scanReport_model_1.ScanReportModel.find({ user: userId, kind: 'web-vulnerability' })
            .select('targetUrl targetHost profile scanStatus startedAt completedAt durationMs requestCount scannerVersion summary errorMessage')
            .sort({ createdAt: -1 })
            .limit(limit);
        return res.json({ success: true, scans: docs.map((d) => toApi(d, false)) });
    }
    catch (err) {
        console.error('[VulnScan] history failed:', err === null || err === void 0 ? void 0 : err.message);
        return fail(res, 500, 'HISTORY_FAILED', 'Scan history could not be loaded.');
    }
});
exports.listWebScans = listWebScans;
const findOwnedScan = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const userId = userIdOf(req);
    if (!userId) {
        fail(res, 401, 'AUTH_REQUIRED', 'Please sign in.');
        return null;
    }
    if (!mongoose_1.default.isValidObjectId(req.params.id)) {
        fail(res, 400, 'INVALID_SCAN_ID', 'Invalid scan id.');
        return null;
    }
    // Ownership enforced in the query: another user's scan id behaves like a missing one.
    const doc = yield scanReport_model_1.ScanReportModel.findOne({ _id: req.params.id, user: userId, kind: 'web-vulnerability' });
    if (!doc) {
        fail(res, 404, 'SCAN_NOT_FOUND', 'Scan not found.');
        return null;
    }
    return doc;
});
/** GET /api/scanners/web-scans/:id — full report (or live progress while running). */
const getWebScan = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const doc = yield findOwnedScan(req, res);
        if (!doc)
            return;
        return res.json({ success: true, scan: toApi(doc, true) });
    }
    catch (err) {
        console.error('[VulnScan] get failed:', err === null || err === void 0 ? void 0 : err.message);
        return fail(res, 500, 'SCAN_LOAD_FAILED', 'The scan could not be loaded.');
    }
});
exports.getWebScan = getWebScan;
/** POST /api/scanners/web-scans/:id/cancel */
const cancelWebScan = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const doc = yield findOwnedScan(req, res);
        if (!doc)
            return;
        if (doc.scanStatus !== 'running' || !(0, orchestrator_1.cancelScan)(doc._id.toString(), String(req.user.userId))) {
            return fail(res, 409, 'SCAN_NOT_RUNNING', 'This scan is not running.');
        }
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, (0, auditService_1.getActorContext)(req)), { action: 'web_vulnerability_scan_cancel_requested', category: 'security scan', source: 'vulnerability_scanner', requestId: (0, auditService_1.getRequestId)(req), metadata: { scanId: doc._id.toString() } }));
        return res.status(202).json({ success: true, message: 'Cancellation requested.' });
    }
    catch (err) {
        console.error('[VulnScan] cancel failed:', err === null || err === void 0 ? void 0 : err.message);
        return fail(res, 500, 'SCAN_CANCEL_FAILED', 'The scan could not be cancelled.');
    }
});
exports.cancelWebScan = cancelWebScan;
