import { Request, Response } from 'express';
import { validateTargetUrl } from '../services/websiteScanner/ssrfProtection';
import { inspectTlsCertificate } from '../services/websiteScanner/tlsScanner';
import { inspectSecurityHeaders } from '../services/websiteScanner/headerScanner';
import { aggregateScanResults } from '../services/websiteScanner/scoreCalculator';
import { recordAuditEvent, getActorContext, getRequestId, safeUrlPreview } from '../services/auditService';

/**
 * Controller handler for POST /api/security/website-scan
 * Assesses public website security indicators while enforcing strict SSRF protections
 */
export const scanWebsiteHandler = async (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    const requestId = getRequestId(req);
    const actor = getActorContext(req);
    const safeUrl = safeUrlPreview(url);

    if (!url || typeof url !== 'string') {
      await recordAuditEvent({
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
      validatedTarget = await validateTargetUrl(url);
    } catch (validationErr: any) {
      await recordAuditEvent({
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

    await recordAuditEvent({
      action: 'website_scan_requested',
      category: 'security scan',
      status: 'success',
      severity: 'low',
      source: 'website_security',
      requestId,
      actorId: actor.actorId,
      actorType: actor.actorType,
      resourceType: 'website',
      resourceId: validatedTarget?.hostname || safeUrl,
      metadata: { url: safeUrl, targetHost: validatedTarget?.hostname || undefined },
    });

    // Step 2 & 3: Run TLS inspection and HTTP header scan concurrently
    const [tlsResult, headerResult] = await Promise.all([
      inspectTlsCertificate(validatedTarget, 6000),
      inspectSecurityHeaders(validatedTarget),
    ]);

    // Step 4: Aggregate into comprehensive security report
    const scanReport = aggregateScanResults(validatedTarget, tlsResult, headerResult);

    const score = scanReport?.scoreBreakdown?.score ?? 0;
    const severity = score < 50 ? 'high' : score < 75 ? 'medium' : 'low';
    const riskLabel = score < 50 ? 'critical' : score < 75 ? 'medium' : 'low';

    await recordAuditEvent({
      action: 'website_scan_completed',
      category: 'security scan',
      status: 'success',
      severity,
      source: 'website_security',
      requestId,
      actorId: actor.actorId,
      actorType: actor.actorType,
      resourceType: 'website',
      resourceId: validatedTarget?.hostname || safeUrl,
      metadata: {
        url: safeUrl,
        score,
        overallRisk: riskLabel,
        issueCount: scanReport?.summary?.totalFindings || 0,
      },
    });

    return res.status(200).json({
      success: true,
      scannedBy: req.user?.email || 'Authorized Analyst',
      report: scanReport,
    });
  } catch (error: any) {
    console.error('Website Security Scan Error:', error?.message || error);
    const requestId = getRequestId(req);
    const actor = getActorContext(req);
    await recordAuditEvent({
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
};
