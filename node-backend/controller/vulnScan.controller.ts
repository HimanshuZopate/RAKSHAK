import { Request, Response } from 'express';
import mongoose from 'mongoose';
import { ScanReportModel, IScanReport } from '../model/scanReport.model';
import { emitToUser } from '../socket/serviceSocket';
import { getActorContext, getRequestId, recordAuditEvent } from '../services/auditService';
import {
  cancelScan,
  checksForProfile,
  getLiveProgress,
  PROFILE_LIMITS,
  ScanRequestError,
  startScan,
} from '../services/vulnScanner/orchestrator';
import { ScanProfile } from '../services/vulnScanner/types';

const PROFILES: ScanProfile[] = ['quick', 'standard', 'comprehensive'];

const fail = (res: Response, status: number, code: string, error: string) => res.status(status).json({ success: false, code, error });

const userIdOf = (req: Request) => (req.user?.userId ? String(req.user.userId) : null);

/** Public API shape of a stored web scan (never includes legacy/internal fields). */
const toApi = (doc: IScanReport, includeDetails: boolean) => ({
  id: doc._id.toString(),
  targetUrl: doc.targetUrl,
  targetHost: doc.targetHost,
  profile: doc.profile,
  scanStatus: doc.scanStatus,
  startedAt: doc.startedAt,
  completedAt: doc.completedAt ?? null,
  durationMs: doc.durationMs ?? null,
  requestCount: doc.requestCount ?? null,
  scannerVersion: doc.scannerVersion,
  summary: doc.summary ?? null,
  errorMessage: doc.errorMessage ?? null,
  ...(includeDetails
    ? {
        findings: doc.webFindings ?? [],
        checks: doc.checks ?? [],
        technologies: doc.technologies ?? [],
        tls: doc.tls ?? null,
        headerSnapshot: doc.headerSnapshot ?? null,
        limitations: doc.limitations ?? [],
        live: doc.scanStatus === 'running' ? getLiveProgress(doc._id.toString()) : null,
      }
    : {}),
});

/** GET /api/scanners/web-scans/profiles — describes what each profile really runs. */
export const getScanProfiles = (_req: Request, res: Response) => {
  res.json({
    success: true,
    profiles: PROFILES.map((profile) => ({
      id: profile,
      checks: checksForProfile(profile).map((c) => ({ id: c.id, label: c.label, phase: c.phase })),
      maxDurationSeconds: PROFILE_LIMITS[profile].maxDurationMs / 1000,
      maxRequests: PROFILE_LIMITS[profile].maxRequests,
    })),
  });
};

/** POST /api/scanners/web-scans  { url, profile, authorizationConfirmed: true } */
export const startWebScan = async (req: Request, res: Response) => {
  const userId = userIdOf(req);
  if (!userId) return fail(res, 401, 'AUTH_REQUIRED', 'Please sign in to run a scan.');
  const { url, profile, authorizationConfirmed } = req.body || {};

  if (authorizationConfirmed !== true) {
    return fail(res, 400, 'AUTHORIZATION_REQUIRED', 'Confirm that you own the target or are explicitly authorised to test it.');
  }
  if (typeof profile !== 'string' || !PROFILES.includes(profile as ScanProfile)) {
    return fail(res, 400, 'INVALID_PROFILE', `profile must be one of: ${PROFILES.join(', ')}.`);
  }
  if (typeof url !== 'string' || !url.trim()) return fail(res, 400, 'INVALID_URL', 'A target URL is required.');

  try {
    const { scanId, snapshot } = await startScan({ userId, url, profile: profile as ScanProfile, emit: emitToUser });
    await recordAuditEvent({
      ...getActorContext(req),
      action: 'web_vulnerability_scan_started',
      category: 'security scan',
      source: 'vulnerability_scanner',
      requestId: getRequestId(req),
      resourceType: 'target',
      resourceId: snapshot.target.slice(0, 200),
      metadata: { profile, scanId, authorizationConfirmed: true },
    });
    return res.status(202).json({ success: true, scan: snapshot });
  } catch (err: any) {
    if (err instanceof ScanRequestError) {
      if (err.code === 'TARGET_REJECTED') {
        await recordAuditEvent({
          ...getActorContext(req),
          action: 'web_vulnerability_scan_rejected',
          category: 'security scan',
          status: 'denied',
          severity: 'low',
          source: 'vulnerability_scanner',
          requestId: getRequestId(req),
          errorCode: err.code,
          metadata: { reason: err.message.slice(0, 200) },
        });
      }
      return fail(res, err.status, err.code, err.message);
    }
    console.error('[VulnScan] start failed:', err?.message);
    return fail(res, 500, 'SCAN_START_FAILED', 'The scan could not be started.');
  }
};

/** GET /api/scanners/web-scans?limit=20 — current user's scan history (summaries only). */
export const listWebScans = async (req: Request, res: Response) => {
  const userId = userIdOf(req);
  if (!userId) return fail(res, 401, 'AUTH_REQUIRED', 'Please sign in.');
  const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 50);
  try {
    const docs = await ScanReportModel.find({ user: userId, kind: 'web-vulnerability' })
      .select('targetUrl targetHost profile scanStatus startedAt completedAt durationMs requestCount scannerVersion summary errorMessage')
      .sort({ createdAt: -1 })
      .limit(limit);
    return res.json({ success: true, scans: docs.map((d) => toApi(d, false)) });
  } catch (err: any) {
    console.error('[VulnScan] history failed:', err?.message);
    return fail(res, 500, 'HISTORY_FAILED', 'Scan history could not be loaded.');
  }
};

const findOwnedScan = async (req: Request, res: Response) => {
  const userId = userIdOf(req);
  if (!userId) {
    fail(res, 401, 'AUTH_REQUIRED', 'Please sign in.');
    return null;
  }
  if (!mongoose.isValidObjectId(req.params.id)) {
    fail(res, 400, 'INVALID_SCAN_ID', 'Invalid scan id.');
    return null;
  }
  // Ownership enforced in the query: another user's scan id behaves like a missing one.
  const doc = await ScanReportModel.findOne({ _id: req.params.id, user: userId, kind: 'web-vulnerability' });
  if (!doc) {
    fail(res, 404, 'SCAN_NOT_FOUND', 'Scan not found.');
    return null;
  }
  return doc;
};

/** GET /api/scanners/web-scans/:id — full report (or live progress while running). */
export const getWebScan = async (req: Request, res: Response) => {
  try {
    const doc = await findOwnedScan(req, res);
    if (!doc) return;
    return res.json({ success: true, scan: toApi(doc, true) });
  } catch (err: any) {
    console.error('[VulnScan] get failed:', err?.message);
    return fail(res, 500, 'SCAN_LOAD_FAILED', 'The scan could not be loaded.');
  }
};

/** POST /api/scanners/web-scans/:id/cancel */
export const cancelWebScan = async (req: Request, res: Response) => {
  try {
    const doc = await findOwnedScan(req, res);
    if (!doc) return;
    if (doc.scanStatus !== 'running' || !cancelScan(doc._id.toString(), String(req.user!.userId))) {
      return fail(res, 409, 'SCAN_NOT_RUNNING', 'This scan is not running.');
    }
    await recordAuditEvent({
      ...getActorContext(req),
      action: 'web_vulnerability_scan_cancel_requested',
      category: 'security scan',
      source: 'vulnerability_scanner',
      requestId: getRequestId(req),
      metadata: { scanId: doc._id.toString() },
    });
    return res.status(202).json({ success: true, message: 'Cancellation requested.' });
  } catch (err: any) {
    console.error('[VulnScan] cancel failed:', err?.message);
    return fail(res, 500, 'SCAN_CANCEL_FAILED', 'The scan could not be cancelled.');
  }
};
