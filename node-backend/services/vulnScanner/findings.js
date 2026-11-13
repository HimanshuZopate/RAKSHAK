"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.severityRank = exports.dedupeFindings = exports.makeFinding = exports.findingId = exports.cleanEvidence = exports.REF = void 0;
const crypto_1 = __importDefault(require("crypto"));
/** Common references reused by several checks. */
exports.REF = {
    owaspHeaders: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    mdnCsp: { title: 'MDN: Content-Security-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy' },
    mdnHsts: { title: 'MDN: Strict-Transport-Security', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' },
    mdnCookies: { title: 'MDN: Set-Cookie', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie' },
    mdnCors: { title: 'MDN: Cross-Origin Resource Sharing', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
    owaspA05: { title: 'OWASP Top 10 A05:2021 Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
    owaspA02: { title: 'OWASP Top 10 A02:2021 Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
    owaspA03: { title: 'OWASP Top 10 A03:2021 Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
    owaspA06: { title: 'OWASP Top 10 A06:2021 Vulnerable and Outdated Components', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
    owaspA01: { title: 'OWASP Top 10 A01:2021 Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
    owaspTlsCheat: { title: 'OWASP Transport Layer Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
    nvd: { title: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/' },
};
const MAX_EVIDENCE_VALUE = 300;
/** Truncates evidence and strips control characters; callers never pass secret values. */
const cleanEvidence = (evidence) => evidence.slice(0, 12).map(({ label, value }) => {
    const text = String(value !== null && value !== void 0 ? value : '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
    return { label, value: text.length > MAX_EVIDENCE_VALUE ? `${text.slice(0, MAX_EVIDENCE_VALUE)}…` : text };
});
exports.cleanEvidence = cleanEvidence;
/** Stable id: the same issue on the same resource always gets the same id (used for de-duplication). */
const findingId = (checkId, key) => `RK-${crypto_1.default.createHash('sha1').update(`${checkId}|${key}`).digest('hex').slice(0, 10).toUpperCase()}`;
exports.findingId = findingId;
const makeFinding = (input) => {
    var _a;
    return ({
        id: (0, exports.findingId)(input.checkId, input.key),
        checkId: input.checkId,
        title: input.title,
        category: input.category,
        owasp: input.owasp,
        severity: input.severity,
        confidence: input.confidence,
        verification: input.verification,
        description: input.description,
        affected: input.affected,
        evidence: (0, exports.cleanEvidence)(input.evidence),
        detection: input.detection,
        impact: input.impact,
        remediation: input.remediation,
        references: (_a = input.references) !== null && _a !== void 0 ? _a : [],
        cveId: input.cveId,
        cves: input.cves,
        firstDetected: new Date().toISOString(),
    });
};
exports.makeFinding = makeFinding;
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
/** Removes duplicate findings (same id), keeping the most severe instance. */
const dedupeFindings = (findings) => {
    const byId = new Map();
    for (const finding of findings) {
        const existing = byId.get(finding.id);
        if (!existing || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity])
            byId.set(finding.id, finding);
    }
    return [...byId.values()].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.title.localeCompare(b.title));
};
exports.dedupeFindings = dedupeFindings;
const severityRank = (severity) => SEVERITY_RANK[severity];
exports.severityRank = severityRank;
