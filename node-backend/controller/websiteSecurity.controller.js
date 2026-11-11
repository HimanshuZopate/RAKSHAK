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
exports.scanWebsiteHandler = void 0;
const ssrfProtection_1 = require("../services/websiteScanner/ssrfProtection");
const tlsScanner_1 = require("../services/websiteScanner/tlsScanner");
const headerScanner_1 = require("../services/websiteScanner/headerScanner");
const scoreCalculator_1 = require("../services/websiteScanner/scoreCalculator");
const auditService_1 = require("../services/auditService");
/**
 * Controller handler for POST /api/security/website-scan
 * Assesses public website security indicators while enforcing strict SSRF protections
 */
const scanWebsiteHandler = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d;
    try {
        const { url } = req.body;
        const requestId = (0, auditService_1.getRequestId)(req);
        const actor = (0, auditService_1.getActorContext)(req);
        const safeUrl = (0, auditService_1.safeUrlPreview)(url);
        if (!url || typeof url !== 'string') {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'website_scan_rejected',
                category: 'security scan',
                status: 'denied',
                severity: 'low',
                source: 'website_security',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { reason: 'missing_url' },
                errorCode: 'MISSING_URL',
            });
            return res.status(400).json({
                success: false,
                error: 'Target website URL is required.',
                code: 'MISSING_URL',
            });
        }
        // Step 1: SSRF Validation and DNS Resolution
        let validatedTarget;
        try {
            validatedTarget = yield (0, ssrfProtection_1.validateTargetUrl)(url);
        }
        catch (validationErr) {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'website_scan_rejected',
                category: 'security scan',
                status: 'denied',
                severity: 'medium',
                source: 'website_security',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { url: safeUrl, reason: 'validation_failed' },
                errorCode: 'SSRF_OR_VALIDATION_ERROR',
            });
            return res.status(400).json({
                success: false,
                error: validationErr.message || 'Invalid website URL or restricted destination.',
                code: 'SSRF_OR_VALIDATION_ERROR',
            });
        }
        yield (0, auditService_1.recordAuditEvent)({
            action: 'website_scan_requested',
            category: 'security scan',
            status: 'success',
            severity: 'low',
            source: 'website_security',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            resourceType: 'website',
            resourceId: (validatedTarget === null || validatedTarget === void 0 ? void 0 : validatedTarget.hostname) || safeUrl,
            metadata: { url: safeUrl, targetHost: (validatedTarget === null || validatedTarget === void 0 ? void 0 : validatedTarget.hostname) || undefined },
        });
        // Step 2 & 3: Run TLS inspection and HTTP header scan concurrently
        const [tlsResult, headerResult] = yield Promise.all([
            (0, tlsScanner_1.inspectTlsCertificate)(validatedTarget, 6000),
            (0, headerScanner_1.inspectSecurityHeaders)(validatedTarget),
        ]);
        // Step 4: Aggregate into comprehensive security report
        const scanReport = (0, scoreCalculator_1.aggregateScanResults)(validatedTarget, tlsResult, headerResult);
        const score = (_b = (_a = scanReport === null || scanReport === void 0 ? void 0 : scanReport.scoreBreakdown) === null || _a === void 0 ? void 0 : _a.score) !== null && _b !== void 0 ? _b : 0;
        const severity = score < 50 ? 'high' : score < 75 ? 'medium' : 'low';
        const riskLabel = score < 50 ? 'critical' : score < 75 ? 'medium' : 'low';
        yield (0, auditService_1.recordAuditEvent)({
            action: 'website_scan_completed',
            category: 'security scan',
            status: 'success',
            severity,
            source: 'website_security',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            resourceType: 'website',
            resourceId: (validatedTarget === null || validatedTarget === void 0 ? void 0 : validatedTarget.hostname) || safeUrl,
            metadata: {
                url: safeUrl,
                score,
                overallRisk: riskLabel,
                issueCount: ((_c = scanReport === null || scanReport === void 0 ? void 0 : scanReport.summary) === null || _c === void 0 ? void 0 : _c.totalFindings) || 0,
            },
        });
        return res.status(200).json({
            success: true,
            scannedBy: ((_d = req.user) === null || _d === void 0 ? void 0 : _d.email) || 'Authorized Analyst',
            report: scanReport,
        });
    }
    catch (error) {
        console.error('Website Security Scan Error:', (error === null || error === void 0 ? void 0 : error.message) || error);
        const requestId = (0, auditService_1.getRequestId)(req);
        const actor = (0, auditService_1.getActorContext)(req);
        yield (0, auditService_1.recordAuditEvent)({
            action: 'website_scan_failed',
            category: 'security scan',
            status: 'failure',
            severity: 'high',
            source: 'website_security',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            metadata: { reason: 'unexpected_scan_error' },
            errorCode: 'SCAN_EXECUTION_ERROR',
        });
        // Safe error message to client without exposing infrastructure internals
        return res.status(500).json({
            success: false,
            error: 'An unexpected error occurred while scanning the target website. Please ensure the domain is publicly reachable.',
            code: 'SCAN_EXECUTION_ERROR',
        });
    }
});
exports.scanWebsiteHandler = scanWebsiteHandler;
