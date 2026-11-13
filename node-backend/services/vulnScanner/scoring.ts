import { CheckOutcome, Finding, Severity } from './types';

/**
 * Risk scoring methodology (transparent and reproducible)
 * ───────────────────────────────────────────────────────
 * 1. Finding severity is assigned by each check from a fixed rubric based on
 *    exploitability, impact and exposure (see the comments in each check).
 * 2. Each finding contributes points = SEVERITY_WEIGHT × EVIDENCE_FACTOR, where the
 *    evidence factor reflects how strongly the issue was demonstrated:
 *      confirmed / misconfiguration → 1.0   (observed directly)
 *      potential, confidence high    → 0.6
 *      potential, confidence medium  → 0.4
 *      potential, confidence low     → 0.25
 *      informational / inconclusive  → 0
 * 3. Points are combined as a probabilistic union:
 *      risk = 100 × (1 − Π(1 − pᵢ / 100))
 *    so the most serious finding dominates, additional findings add with
 *    diminishing returns, and many low issues can never look "critical".
 * 4. Security score = 100 − risk. Risk level thresholds:
 *      ≥ 70 critical · ≥ 45 high · ≥ 20 medium · > 0 low · 0 minimal
 * The score summarises the checks performed; it is not a certification.
 */

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 40, high: 25, medium: 10, low: 3, info: 0 };

export const evidenceFactor = (finding: Finding): number => {
  switch (finding.verification) {
    case 'confirmed':
    case 'misconfiguration':
      return 1;
    case 'potential':
      return finding.confidence === 'high' ? 0.6 : finding.confidence === 'medium' ? 0.4 : 0.25;
    default:
      return 0;
  }
};

export const findingPoints = (finding: Finding) => SEVERITY_WEIGHT[finding.severity] * evidenceFactor(finding);

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal';

export interface ScanSummary {
  riskScore: number;
  securityScore: number;
  riskLevel: RiskLevel;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byVerification: Record<Finding['verification'], number>;
  confirmed: number;
  potential: number;
  checksTotal: number;
  checksCompleted: number;
  checksInconclusive: number;
  checksSkipped: number;
  checksFailed: number;
  topContributors: Array<{ id: string; title: string; points: number }>;
  methodology: string;
}

export const riskLevelFor = (risk: number): RiskLevel =>
  risk >= 70 ? 'critical' : risk >= 45 ? 'high' : risk >= 20 ? 'medium' : risk > 0 ? 'low' : 'minimal';

export const summarize = (findings: Finding[], checks: CheckOutcome[]): ScanSummary => {
  const remaining = findings.reduce((acc, f) => acc * (1 - Math.min(findingPoints(f), 100) / 100), 1);
  const riskScore = Math.round(100 * (1 - remaining));
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byVerification: Record<Finding['verification'], number> = { confirmed: 0, misconfiguration: 0, potential: 0, informational: 0, inconclusive: 0 };
  for (const f of findings) {
    bySeverity[f.severity] += 1;
    byVerification[f.verification] += 1;
  }
  return {
    riskScore,
    securityScore: 100 - riskScore,
    riskLevel: riskLevelFor(riskScore),
    totalFindings: findings.length,
    bySeverity,
    byVerification,
    confirmed: byVerification.confirmed + byVerification.misconfiguration,
    potential: byVerification.potential,
    checksTotal: checks.length,
    checksCompleted: checks.filter((c) => c.status === 'passed' || c.status === 'issues').length,
    checksInconclusive: checks.filter((c) => c.status === 'inconclusive').length,
    checksSkipped: checks.filter((c) => c.status === 'skipped' || c.status === 'cancelled').length,
    checksFailed: checks.filter((c) => c.status === 'error').length,
    topContributors: findings
      .map((f) => ({ id: f.id, title: f.title, points: Math.round(findingPoints(f) * 10) / 10 }))
      .filter((c) => c.points > 0)
      .sort((a, b) => b.points - a.points)
      .slice(0, 5),
    methodology:
      'risk = 100 × (1 − Π(1 − pᵢ/100)), pᵢ = severity weight (critical 40, high 25, medium 10, low 3, info 0) × evidence factor (confirmed/misconfiguration 1.0; potential 0.6/0.4/0.25 by confidence; informational 0). Security score = 100 − risk.',
  };
};
