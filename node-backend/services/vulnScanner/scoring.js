"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.summarize = exports.riskLevelFor = exports.findingPoints = exports.evidenceFactor = exports.SEVERITY_WEIGHT = void 0;
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
exports.SEVERITY_WEIGHT = { critical: 40, high: 25, medium: 10, low: 3, info: 0 };
const evidenceFactor = (finding) => {
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
exports.evidenceFactor = evidenceFactor;
const findingPoints = (finding) => exports.SEVERITY_WEIGHT[finding.severity] * (0, exports.evidenceFactor)(finding);
exports.findingPoints = findingPoints;
const riskLevelFor = (risk) => risk >= 70 ? 'critical' : risk >= 45 ? 'high' : risk >= 20 ? 'medium' : risk > 0 ? 'low' : 'minimal';
exports.riskLevelFor = riskLevelFor;
const summarize = (findings, checks) => {
    const remaining = findings.reduce((acc, f) => acc * (1 - Math.min((0, exports.findingPoints)(f), 100) / 100), 1);
    const riskScore = Math.round(100 * (1 - remaining));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byVerification = { confirmed: 0, misconfiguration: 0, potential: 0, informational: 0, inconclusive: 0 };
    for (const f of findings) {
        bySeverity[f.severity] += 1;
        byVerification[f.verification] += 1;
    }
    return {
        riskScore,
        securityScore: 100 - riskScore,
        riskLevel: (0, exports.riskLevelFor)(riskScore),
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
            .map((f) => ({ id: f.id, title: f.title, points: Math.round((0, exports.findingPoints)(f) * 10) / 10 }))
            .filter((c) => c.points > 0)
            .sort((a, b) => b.points - a.points)
            .slice(0, 5),
        methodology: 'risk = 100 × (1 − Π(1 − pᵢ/100)), pᵢ = severity weight (critical 40, high 25, medium 10, low 3, info 0) × evidence factor (confirmed/misconfiguration 1.0; potential 0.6/0.4/0.25 by confidence; informational 0). Security score = 100 − risk.',
    };
};
exports.summarize = summarize;
