/**
 * Shared types for the RAKSHAK web vulnerability assessment engine.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

/**
 * - confirmed:        directly demonstrated by a probe (e.g. open redirect Location header)
 * - misconfiguration: configuration observed directly in responses (e.g. missing HSTS)
 * - potential:        indicator that needs manual verification (e.g. version-based CVE match)
 * - informational:    observation without direct risk (e.g. detected technology)
 * - inconclusive:     the check could not reach a reliable verdict
 */
export type Verification = 'confirmed' | 'misconfiguration' | 'potential' | 'informational' | 'inconclusive';

export type ScanProfile = 'quick' | 'standard' | 'comprehensive';

export interface Evidence {
  label: string;
  value: string;
}

export interface Reference {
  title: string;
  url: string;
}

export interface CveRecord {
  id: string;
  cvss: number | null;
  cvssVersion: string | null;
  severity: string | null;
  description: string;
  published: string | null;
  url: string;
}

export interface Finding {
  id: string;
  checkId: string;
  title: string;
  category: string;
  owasp?: string;
  severity: Severity;
  confidence: Confidence;
  verification: Verification;
  description: string;
  affected: string;
  evidence: Evidence[];
  detection: string;
  impact: string;
  remediation: string;
  references: Reference[];
  cveId?: string;
  cves?: CveRecord[];
  firstDetected: string;
}

export type CheckStatus = 'passed' | 'issues' | 'inconclusive' | 'skipped' | 'error' | 'cancelled';

export interface CheckOutcome {
  id: string;
  label: string;
  phase: string;
  status: CheckStatus;
  note?: string;
  durationMs: number;
  requests: number;
}

export interface TechnologyInfo {
  name: string;
  version: string | null;
  category: string;
  confidence: Confidence;
  evidence: string;
  cpe?: string;
}

export interface TlsInfo {
  available: boolean;
  negotiatedProtocol: string | null;
  cipher: string | null;
  supportedProtocols: Record<string, 'supported' | 'not supported' | 'inconclusive'>;
  certificate: {
    subject: string | null;
    issuer: string | null;
    subjectAltNames: string[];
    validFrom: string | null;
    validTo: string | null;
    daysRemaining: number | null;
    fingerprint256: string | null;
    trusted: boolean;
    trustError: string | null;
    hostnameMatches: boolean;
  } | null;
}

export interface HeaderSnapshot {
  url: string;
  status: number;
  headers: Record<string, string>;
}
