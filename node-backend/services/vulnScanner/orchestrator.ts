import { ScanReportModel, WebScanStatus } from '../../model/scanReport.model';
import { recordAuditEvent } from '../auditService';
import { CheckDefinition, ScanContext } from './context';
import { dedupeFindings } from './findings';
import { ProbeError, ScanHttpClient } from './safeHttp';
import { summarize, ScanSummary } from './scoring';
import { parseScanTarget, resolveAllowedAddress, TargetRejectedError } from './targetGuard';
import { CheckOutcome, Finding, ScanProfile } from './types';
import { connectivityCheck } from './checks/connectivity';
import { headersCheck } from './checks/headers';
import { tlsCheck } from './checks/tls';
import { cookiesCheck } from './checks/cookies';
import { corsCheck } from './checks/cors';
import { methodsCheck } from './checks/methods';
import { disclosureCheck, exposedResourcesCheck } from './checks/exposure';
import { contentCheck } from './checks/content';
import { fingerprintCheck } from './checks/fingerprint';
import { reflectedInputCheck, sqlInjectionCheck, openRedirectCheck } from './checks/activeProbes';
import { cveCorrelationCheck } from './checks/cveCorrelation';

export const SCANNER_VERSION = '1.0.0';

/** Ordered check pipeline. Each check declares which profiles run it. */
export const CHECKS: CheckDefinition[] = [
  connectivityCheck,
  headersCheck,
  tlsCheck,
  cookiesCheck,
  corsCheck,
  methodsCheck,
  disclosureCheck,
  exposedResourcesCheck,
  contentCheck,
  fingerprintCheck,
  reflectedInputCheck,
  sqlInjectionCheck,
  openRedirectCheck,
  cveCorrelationCheck,
];

export const PROFILE_LIMITS: Record<ScanProfile, { maxDurationMs: number; maxRequests: number; concurrency: number }> = {
  quick: { maxDurationMs: 90_000, maxRequests: 40, concurrency: 3 },
  standard: { maxDurationMs: 180_000, maxRequests: 150, concurrency: 4 },
  comprehensive: { maxDurationMs: 360_000, maxRequests: 260, concurrency: 4 },
};

const MAX_CONCURRENT_SCANS = 3;

const BASE_LIMITATIONS = [
  'Only the submitted URL and a small fixed set of well-known paths are analysed; the site is not crawled.',
  'No login is performed, so authenticated areas are not assessed.',
  'Path traversal, command injection, authentication and business-logic flaws are not tested because they cannot be verified safely without exploitation.',
  'Active checks send harmless probes only; XSS and SQL injection results are indicators that require manual confirmation.',
];

const PROFILE_LIMITATIONS: Record<ScanProfile, string[]> = {
  quick: ['Quick profile: method, disclosure, exposed-resource, content, vulnerability-probe and CVE checks were not run.'],
  standard: ['Standard profile: CVE correlation, source-map discovery and the extended exposed-path list were not run.'],
  comprehensive: ['CVE matches are based on detected version strings and may not reflect patches backported by operating-system vendors.'],
};

export const checksForProfile = (profile: ScanProfile) => CHECKS.filter((c) => c.profiles.includes(profile));

export interface ProgressSnapshot {
  scanId: string;
  scanStatus: WebScanStatus;
  profile: ScanProfile;
  target: string;
  currentCheck: { id: string; label: string; phase: string } | null;
  completed: number;
  total: number;
  checks: Array<CheckOutcome | { id: string; label: string; phase: string; status: 'pending' | 'running' }>;
  findingsCount: number;
  bySeverity: Record<string, number>;
  requests: number;
  elapsedMs: number;
}

type Emit = (userId: string, event: string, payload: unknown) => void;

interface RunningScan {
  id: string;
  userId: string;
  controller: AbortController;
  stopReason: 'cancelled' | 'timeout' | null;
  snapshot: ProgressSnapshot;
}

const running = new Map<string, RunningScan>();

export class ScanRequestError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

export const getLiveProgress = (scanId: string): ProgressSnapshot | null => running.get(scanId)?.snapshot ?? null;

export const activeScanForUser = (userId: string) => [...running.values()].find((s) => s.userId === userId) || null;

export const cancelScan = (scanId: string, userId: string): boolean => {
  const scan = running.get(scanId);
  if (!scan || scan.userId !== userId) return false;
  scan.stopReason = 'cancelled';
  scan.controller.abort();
  return true;
};

/** Marks scans left "running" by a previous process (crash/restart) as failed. */
export const recoverInterruptedScans = async () => {
  try {
    await ScanReportModel.updateMany(
      { kind: 'web-vulnerability', scanStatus: 'running' },
      { $set: { scanStatus: 'failed', errorMessage: 'The scan was interrupted because the server restarted.', completedAt: new Date() } }
    );
  } catch (err: any) {
    console.warn('[VulnScanner] Could not recover interrupted scans:', err?.message);
  }
};

export interface StartScanInput {
  userId: string;
  url: unknown;
  profile: ScanProfile;
  emit: Emit;
}

export const startScan = async ({ userId, url, profile, emit }: StartScanInput) => {
  if (activeScanForUser(userId)) throw new ScanRequestError(409, 'SCAN_ALREADY_RUNNING', 'You already have a scan in progress. Wait for it to finish or cancel it.');
  if (running.size >= MAX_CONCURRENT_SCANS) throw new ScanRequestError(503, 'SCANNER_BUSY', 'The scanner is busy. Please try again in a minute.');

  let target;
  try {
    target = parseScanTarget(url);
    await resolveAllowedAddress(target.hostname, target.port); // fail fast before creating a record
  } catch (err) {
    if (err instanceof TargetRejectedError) throw new ScanRequestError(400, 'TARGET_REJECTED', err.message);
    throw err;
  }

  const doc = await ScanReportModel.create({
    user: userId,
    service: 'Vulnerability Scanner',
    kind: 'web-vulnerability',
    scanStatus: 'running',
    targetUrl: target.url.href,
    targetHost: target.hostname,
    profile,
    startedAt: new Date(),
    scannerVersion: SCANNER_VERSION,
  });
  const scanId = doc._id.toString();
  const checks = checksForProfile(profile);
  const limits = PROFILE_LIMITS[profile];
  const controller = new AbortController();

  const scan: RunningScan = {
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
      checks: checks.map((c) => ({ id: c.id, label: c.label, phase: c.phase, status: 'pending' as const })),
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
};

const executeScan = async (
  scan: RunningScan,
  target: ReturnType<typeof parseScanTarget>,
  profile: ScanProfile,
  checks: CheckDefinition[],
  limits: (typeof PROFILE_LIMITS)[ScanProfile],
  emit: Emit
) => {
  const startedAt = Date.now();
  const http = new ScanHttpClient(scan.controller.signal, limits.maxRequests, limits.concurrency);
  const ctx: ScanContext = {
    target,
    profile,
    http,
    signal: scan.controller.signal,
    data: { technologies: [], limitations: [] },
  };
  const timeout = setTimeout(() => {
    scan.stopReason = scan.stopReason ?? 'timeout';
    scan.controller.abort();
  }, limits.maxDurationMs);

  const outcomes: CheckOutcome[] = [];
  const findings: Finding[] = [];
  let fatalError: string | null = null;

  const publish = () => {
    const unique = dedupeFindings(findings);
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    unique.forEach((f) => { bySeverity[f.severity] += 1; });
    scan.snapshot = {
      ...scan.snapshot,
      completed: outcomes.length,
      checks: checks.map((c) => outcomes.find((o) => o.id === c.id) ?? { id: c.id, label: c.label, phase: c.phase, status: scan.snapshot.currentCheck?.id === c.id ? 'running' as const : 'pending' as const }),
      findingsCount: unique.length,
      bySeverity,
      requests: http.requestCount,
      elapsedMs: Date.now() - startedAt,
    };
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
        const res = await check.run(ctx);
        findings.push(...res.findings);
        outcomes.push({ id: check.id, label: check.label, phase: check.phase, status: res.status, note: res.note, durationMs: Date.now() - checkStart, requests: http.requestCount - requestsBefore });
      } catch (err: any) {
        const aborted = scan.controller.signal.aborted || (err instanceof ProbeError && err.code === 'CANCELLED') || err?.message === 'CANCELLED';
        const message = aborted
          ? scan.stopReason === 'timeout' ? 'Stopped: scan time limit reached.' : 'Stopped: scan cancelled.'
          : err instanceof ProbeError || err instanceof TargetRejectedError ? err.message : 'Unexpected error while running this check.';
        if (!aborted && !(err instanceof ProbeError) && !(err instanceof TargetRejectedError)) {
          console.error(`[VulnScanner] check ${check.id} failed:`, err?.message);
        }
        outcomes.push({
          id: check.id, label: check.label, phase: check.phase,
          status: aborted ? 'cancelled' : err instanceof ProbeError && err.code === 'BUDGET' ? 'inconclusive' : 'error',
          note: message, durationMs: Date.now() - checkStart, requests: http.requestCount - requestsBefore,
        });
        if (check.critical && !aborted) fatalError = `Target could not be reached: ${message}`;
      }
      scan.snapshot.currentCheck = null;
      publish();
    }
  } finally {
    clearTimeout(timeout);
  }

  const unique = dedupeFindings(findings);
  const summary: ScanSummary = summarize(unique, outcomes);
  const scanStatus: WebScanStatus =
    scan.stopReason === 'cancelled' ? 'cancelled' : scan.stopReason === 'timeout' ? 'timed_out' : fatalError ? 'failed' : 'completed';
  const limitations = [...BASE_LIMITATIONS, ...PROFILE_LIMITATIONS[profile], ...ctx.data.limitations];

  try {
    await ScanReportModel.updateOne(
      { _id: scan.id },
      {
        $set: {
          scanStatus,
          completedAt: new Date(),
          durationMs: Date.now() - startedAt,
          requestCount: http.requestCount,
          summary,
          webFindings: unique,
          checks: outcomes,
          technologies: ctx.data.technologies,
          tls: ctx.data.tls ?? null,
          headerSnapshot: ctx.data.headerSnapshot ?? null,
          limitations,
          errorMessage: fatalError,
        },
      }
    );
  } catch (err: any) {
    console.error('[VulnScanner] Failed to save scan results:', err?.message);
  }

  await recordAuditEvent({
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

  scan.snapshot = { ...scan.snapshot, scanStatus, currentCheck: null, elapsedMs: Date.now() - startedAt };
  emit(scan.userId, 'vuln-scan:complete', { scanId: scan.id, scanStatus, summary });
  running.delete(scan.id);
};
