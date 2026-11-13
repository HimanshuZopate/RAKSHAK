import { HttpResult, ScanHttpClient } from './safeHttp';
import { ScanTarget } from './targetGuard';
import { CheckStatus, Finding, HeaderSnapshot, ScanProfile, TechnologyInfo, TlsInfo } from './types';

/** Shared, per-scan state that checks read from and write to. */
export interface ScanData {
  base?: HttpResult; // final response for the target URL (after redirects)
  httpsAvailable?: boolean;
  httpRedirectsToHttps?: boolean | null;
  notFoundBaseline?: { status: number; length: number; snippetHash: string } | null;
  tls?: TlsInfo;
  technologies: TechnologyInfo[];
  headerSnapshot?: HeaderSnapshot;
  limitations: string[];
}

export interface ScanContext {
  target: ScanTarget;
  profile: ScanProfile;
  http: ScanHttpClient;
  signal: AbortSignal;
  data: ScanData;
}

export interface CheckResult {
  status: Exclude<CheckStatus, 'cancelled'>;
  findings: Finding[];
  note?: string;
}

export interface CheckDefinition {
  id: string;
  label: string;
  phase: string;
  profiles: ScanProfile[];
  /** When true and the check fails, the remaining checks cannot run (target unreachable). */
  critical?: boolean;
  run: (ctx: ScanContext) => Promise<CheckResult>;
}

export const result = (findings: Finding[], note?: string): CheckResult => ({
  status: findings.some((f) => f.severity !== 'info') ? 'issues' : 'passed',
  findings,
  note,
});

export const inconclusive = (note: string, findings: Finding[] = []): CheckResult => ({ status: 'inconclusive', findings, note });

export const skipped = (note: string): CheckResult => ({ status: 'skipped', findings: [], note });

export const ALL_PROFILES: ScanProfile[] = ['quick', 'standard', 'comprehensive'];
export const STANDARD_UP: ScanProfile[] = ['standard', 'comprehensive'];
export const COMPREHENSIVE_ONLY: ScanProfile[] = ['comprehensive'];
