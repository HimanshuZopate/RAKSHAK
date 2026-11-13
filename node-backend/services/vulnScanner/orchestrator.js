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
Object.defineProperty(exports, "__esModule", { value: true });
exports.startScan = exports.recoverInterruptedScans = exports.cancelScan = exports.activeScanForUser = exports.getLiveProgress = exports.ScanRequestError = exports.checksForProfile = exports.PROFILE_LIMITS = exports.CHECKS = exports.SCANNER_VERSION = void 0;
const scanReport_model_1 = require("../../model/scanReport.model");
const auditService_1 = require("../auditService");
const findings_1 = require("./findings");
const safeHttp_1 = require("./safeHttp");
const scoring_1 = require("./scoring");
const targetGuard_1 = require("./targetGuard");
const connectivity_1 = require("./checks/connectivity");
const headers_1 = require("./checks/headers");
const tls_1 = require("./checks/tls");
const cookies_1 = require("./checks/cookies");
const cors_1 = require("./checks/cors");
const methods_1 = require("./checks/methods");
const exposure_1 = require("./checks/exposure");
const content_1 = require("./checks/content");
const fingerprint_1 = require("./checks/fingerprint");
const activeProbes_1 = require("./checks/activeProbes");
const cveCorrelation_1 = require("./checks/cveCorrelation");
exports.SCANNER_VERSION = '1.0.0';
/** Ordered check pipeline. Each check declares which profiles run it. */
exports.CHECKS = [
    connectivity_1.connectivityCheck,
    headers_1.headersCheck,
    tls_1.tlsCheck,
    cookies_1.cookiesCheck,
    cors_1.corsCheck,
    methods_1.methodsCheck,
    exposure_1.disclosureCheck,
    exposure_1.exposedResourcesCheck,
    content_1.contentCheck,
    fingerprint_1.fingerprintCheck,
    activeProbes_1.reflectedInputCheck,
    activeProbes_1.sqlInjectionCheck,
    activeProbes_1.openRedirectCheck,
    cveCorrelation_1.cveCorrelationCheck,
];
exports.PROFILE_LIMITS = {
    quick: { maxDurationMs: 90000, maxRequests: 40, concurrency: 3 },
    standard: { maxDurationMs: 180000, maxRequests: 150, concurrency: 4 },
    comprehensive: { maxDurationMs: 360000, maxRequests: 260, concurrency: 4 },
};
const MAX_CONCURRENT_SCANS = 3;
const BASE_LIMITATIONS = [
    'Only the submitted URL and a small fixed set of well-known paths are analysed; the site is not crawled.',
    'No login is performed, so authenticated areas are not assessed.',
    'Path traversal, command injection, authentication and business-logic flaws are not tested because they cannot be verified safely without exploitation.',
    'Active checks send harmless probes only; XSS and SQL injection results are indicators that require manual confirmation.',
];
const PROFILE_LIMITATIONS = {
    quick: ['Quick profile: method, disclosure, exposed-resource, content, vulnerability-probe and CVE checks were not run.'],
    standard: ['Standard profile: CVE correlation, source-map discovery and the extended exposed-path list were not run.'],
    comprehensive: ['CVE matches are based on detected version strings and may not reflect patches backported by operating-system vendors.'],
};
const checksForProfile = (profile) => exports.CHECKS.filter((c) => c.profiles.includes(profile));
exports.checksForProfile = checksForProfile;
const running = new Map();
class ScanRequestError extends Error {
    constructor(status, code, message) {
        super(message);
        this.status = status;
        this.code = code;
    }
}
exports.ScanRequestError = ScanRequestError;
const getLiveProgress = (scanId) => { var _a, _b; return (_b = (_a = running.get(scanId)) === null || _a === void 0 ? void 0 : _a.snapshot) !== null && _b !== void 0 ? _b : null; };
exports.getLiveProgress = getLiveProgress;
const activeScanForUser = (userId) => [...running.values()].find((s) => s.userId === userId) || null;
exports.activeScanForUser = activeScanForUser;
const cancelScan = (scanId, userId) => {
    const scan = running.get(scanId);
    if (!scan || scan.userId !== userId)
        return false;
    scan.stopReason = 'cancelled';
    scan.controller.abort();
    return true;
};
exports.cancelScan = cancelScan;
/** Marks scans left "running" by a previous process (crash/restart) as failed. */
const recoverInterruptedScans = () => __awaiter(void 0, void 0, void 0, function* () {
    try {
        yield scanReport_model_1.ScanReportModel.updateMany({ kind: 'web-vulnerability', scanStatus: 'running' }, { $set: { scanStatus: 'failed', errorMessage: 'The scan was interrupted because the server restarted.', completedAt: new Date() } });
    }
    catch (err) {
        console.warn('[VulnScanner] Could not recover interrupted scans:', err === null || err === void 0 ? void 0 : err.message);
    }
});
exports.recoverInterruptedScans = recoverInterruptedScans;
const startScan = ({ userId, url, profile, emit }) => __awaiter(void 0, void 0, void 0, function* () {
    if ((0, exports.activeScanForUser)(userId))
        throw new ScanRequestError(409, 'SCAN_ALREADY_RUNNING', 'You already have a scan in progress. Wait for it to finish or cancel it.');
    if (running.size >= MAX_CONCURRENT_SCANS)
        throw new ScanRequestError(503, 'SCANNER_BUSY', 'The scanner is busy. Please try again in a minute.');
    let target;
    try {
        target = (0, targetGuard_1.parseScanTarget)(url);
        yield (0, targetGuard_1.resolveAllowedAddress)(target.hostname, target.port); // fail fast before creating a record
    }
    catch (err) {
        if (err instanceof targetGuard_1.TargetRejectedError)
            throw new ScanRequestError(400, 'TARGET_REJECTED', err.message);
        throw err;
    }
    const doc = yield scanReport_model_1.ScanReportModel.create({
        user: userId,
        service: 'Vulnerability Scanner',
        kind: 'web-vulnerability',
        scanStatus: 'running',
        targetUrl: target.url.href,
        targetHost: target.hostname,
        profile,
        startedAt: new Date(),
        scannerVersion: exports.SCANNER_VERSION,
    });
    const scanId = doc._id.toString();
    const checks = (0, exports.checksForProfile)(profile);
    const limits = exports.PROFILE_LIMITS[profile];
    const controller = new AbortController();
    const scan = {
        id: scanId,
        userId,
        controller,
        stopReason: null,
        snapshot: {
            scanId,
            scanStatus: 'running',
            profile,
            target: target.url.href,
            currentCheck: null,
            completed: 0,
            total: checks.length,
            checks: checks.map((c) => ({ id: c.id, label: c.label, phase: c.phase, status: 'pending' })),
            findingsCount: 0,
            bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            requests: 0,
            elapsedMs: 0,
        },
    };
    running.set(scanId, scan);
    // Run asynchronously; the HTTP request returns immediately with the scan id.
    void executeScan(scan, target, profile, checks, limits, emit);
    return { scanId, snapshot: scan.snapshot };
});
exports.startScan = startScan;
const executeScan = (scan, target, profile, checks, limits, emit) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    const startedAt = Date.now();
    const http = new safeHttp_1.ScanHttpClient(scan.controller.signal, limits.maxRequests, limits.concurrency);
    const ctx = {
        target,
        profile,
        http,
        signal: scan.controller.signal,
        data: { technologies: [], limitations: [] },
    };
    const timeout = setTimeout(() => {
        var _a;
        scan.stopReason = (_a = scan.stopReason) !== null && _a !== void 0 ? _a : 'timeout';
        scan.controller.abort();
    }, limits.maxDurationMs);
    const outcomes = [];
    const findings = [];
    let fatalError = null;
    const publish = () => {
        const unique = (0, findings_1.dedupeFindings)(findings);
        const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        unique.forEach((f) => { bySeverity[f.severity] += 1; });
        scan.snapshot = Object.assign(Object.assign({}, scan.snapshot), { completed: outcomes.length, checks: checks.map((c) => { var _a, _b; return (_a = outcomes.find((o) => o.id === c.id)) !== null && _a !== void 0 ? _a : { id: c.id, label: c.label, phase: c.phase, status: ((_b = scan.snapshot.currentCheck) === null || _b === void 0 ? void 0 : _b.id) === c.id ? 'running' : 'pending' }; }), findingsCount: unique.length, bySeverity, requests: http.requestCount, elapsedMs: Date.now() - startedAt });
        emit(scan.userId, 'vuln-scan:progress', scan.snapshot);
    };
    try {
        for (const check of checks) {
            if (scan.controller.signal.aborted || fatalError) {
                outcomes.push({
                    id: check.id, label: check.label, phase: check.phase,
                    status: fatalError ? 'skipped' : 'cancelled',
                    note: fatalError ? 'Not run because the target could not be reached.' : scan.stopReason === 'timeout' ? 'Not run: scan time limit reached.' : 'Not run: scan cancelled.',
                    durationMs: 0, requests: 0,
                });
                continue;
            }
            scan.snapshot.currentCheck = { id: check.id, label: check.label, phase: check.phase };
            publish();
            const checkStart = Date.now();
            const requestsBefore = http.requestCount;
            try {
                const res = yield check.run(ctx);
                findings.push(...res.findings);
                outcomes.push({ id: check.id, label: check.label, phase: check.phase, status: res.status, note: res.note, durationMs: Date.now() - checkStart, requests: http.requestCount - requestsBefore });
            }
            catch (err) {
                const aborted = scan.controller.signal.aborted || (err instanceof safeHttp_1.ProbeError && err.code === 'CANCELLED') || (err === null || err === void 0 ? void 0 : err.message) === 'CANCELLED';
                const message = aborted
                    ? scan.stopReason === 'timeout' ? 'Stopped: scan time limit reached.' : 'Stopped: scan cancelled.'
                    : err instanceof safeHttp_1.ProbeError || err instanceof targetGuard_1.TargetRejectedError ? err.message : 'Unexpected error while running this check.';
                if (!aborted && !(err instanceof safeHttp_1.ProbeError) && !(err instanceof targetGuard_1.TargetRejectedError)) {
                    console.error(`[VulnScanner] check ${check.id} failed:`, err === null || err === void 0 ? void 0 : err.message);
                }
                outcomes.push({
                    id: check.id, label: check.label, phase: check.phase,
                    status: aborted ? 'cancelled' : err instanceof safeHttp_1.ProbeError && err.code === 'BUDGET' ? 'inconclusive' : 'error',
                    note: message, durationMs: Date.now() - checkStart, requests: http.requestCount - requestsBefore,
                });
                if (check.critical && !aborted)
                    fatalError = `Target could not be reached: ${message}`;
            }
            scan.snapshot.currentCheck = null;
            publish();
        }
    }
    finally {
        clearTimeout(timeout);
    }
    const unique = (0, findings_1.dedupeFindings)(findings);
    const summary = (0, scoring_1.summarize)(unique, outcomes);
    const scanStatus = scan.stopReason === 'cancelled' ? 'cancelled' : scan.stopReason === 'timeout' ? 'timed_out' : fatalError ? 'failed' : 'completed';
    const limitations = [...BASE_LIMITATIONS, ...PROFILE_LIMITATIONS[profile], ...ctx.data.limitations];
    try {
        yield scanReport_model_1.ScanReportModel.updateOne({ _id: scan.id }, {
            $set: {
                scanStatus,
                completedAt: new Date(),
                durationMs: Date.now() - startedAt,
                requestCount: http.requestCount,
                summary,
                webFindings: unique,
                checks: outcomes,
                technologies: ctx.data.technologies,
                tls: (_a = ctx.data.tls) !== null && _a !== void 0 ? _a : null,
                headerSnapshot: (_b = ctx.data.headerSnapshot) !== null && _b !== void 0 ? _b : null,
                limitations,
                errorMessage: fatalError,
            },
        });
    }
    catch (err) {
        console.error('[VulnScanner] Failed to save scan results:', err === null || err === void 0 ? void 0 : err.message);
    }
    yield (0, auditService_1.recordAuditEvent)({
        actorId: scan.userId,
        actorType: 'user',
        action: `web_vulnerability_scan_${scanStatus}`,
        category: 'security scan',
        status: scanStatus === 'completed' ? 'success' : scanStatus === 'cancelled' ? 'partial' : 'failure',
        severity: summary.riskLevel === 'critical' || summary.riskLevel === 'high' ? 'high' : summary.riskLevel === 'medium' ? 'medium' : 'low',
        source: 'vulnerability_scanner',
        resourceType: 'target',
        resourceId: target.hostname,
        metadata: { profile, riskScore: summary.riskScore, findings: summary.totalFindings, requests: http.requestCount, scanId: scan.id },
    });
    scan.snapshot = Object.assign(Object.assign({}, scan.snapshot), { scanStatus, currentCheck: null, elapsedMs: Date.now() - startedAt });
    emit(scan.userId, 'vuln-scan:complete', { scanId: scan.id, scanStatus, summary });
    running.delete(scan.id);
});
