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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.cveCorrelationCheck = exports.lookupCves = exports.parseNvdResponse = void 0;
const axios_1 = __importDefault(require("axios"));
const context_1 = require("../context");
const findings_1 = require("../findings");
/**
 * CVE correlation via the official NVD CVE API 2.0 (comprehensive profile).
 * https://nvd.nist.gov/developers/vulnerabilities
 *
 * Query: cpeName=<cpe with exact version>&isVulnerable — NVD evaluates the CVE
 * configurations (including versionStart/versionEnd ranges) and returns only
 * CVEs where that exact version is marked vulnerable.
 *
 * Rate limits (NVD): 5 requests / 30 s without a key, 50 / 30 s with NVD_API_KEY.
 * Results are cached in memory for 24 h. External availability is never
 * required for the rest of the scan.
 */
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE_TTL_MS = 24 * 3600 * 1000;
const MAX_LISTED = 10;
const cache = new Map();
let nextSlot = 0;
const spacingMs = () => (process.env.NVD_API_KEY ? 700 : 6500);
/** Serialises NVD calls process-wide to respect the published rate limit. */
const waitForSlot = (signal) => __awaiter(void 0, void 0, void 0, function* () {
    const now = Date.now();
    const at = Math.max(now, nextSlot);
    nextSlot = at + spacingMs();
    const delay = at - now;
    if (delay > 0) {
        yield new Promise((resolve, reject) => {
            const timer = setTimeout(resolve, delay);
            signal.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('CANCELLED')); }, { once: true });
        });
    }
});
const severityFromCvss = (score) => {
    if (score === null)
        return 'medium';
    if (score >= 9)
        return 'critical';
    if (score >= 7)
        return 'high';
    if (score >= 4)
        return 'medium';
    return score > 0 ? 'low' : 'info';
};
const parseNvdResponse = (data) => {
    var _a;
    const records = ((data === null || data === void 0 ? void 0 : data.vulnerabilities) || []).map((item) => {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q;
        const cve = (item === null || item === void 0 ? void 0 : item.cve) || {};
        const metric = ((_b = (_a = cve.metrics) === null || _a === void 0 ? void 0 : _a.cvssMetricV31) === null || _b === void 0 ? void 0 : _b[0]) || ((_d = (_c = cve.metrics) === null || _c === void 0 ? void 0 : _c.cvssMetricV30) === null || _d === void 0 ? void 0 : _d[0]) || ((_f = (_e = cve.metrics) === null || _e === void 0 ? void 0 : _e.cvssMetricV40) === null || _f === void 0 ? void 0 : _f[0]) || ((_h = (_g = cve.metrics) === null || _g === void 0 ? void 0 : _g.cvssMetricV2) === null || _h === void 0 ? void 0 : _h[0]);
        const cvss = (_k = (_j = metric === null || metric === void 0 ? void 0 : metric.cvssData) === null || _j === void 0 ? void 0 : _j.baseScore) !== null && _k !== void 0 ? _k : null;
        return {
            id: String(cve.id || ''),
            cvss: typeof cvss === 'number' ? cvss : null,
            cvssVersion: (_m = (_l = metric === null || metric === void 0 ? void 0 : metric.cvssData) === null || _l === void 0 ? void 0 : _l.version) !== null && _m !== void 0 ? _m : null,
            severity: ((_o = metric === null || metric === void 0 ? void 0 : metric.cvssData) === null || _o === void 0 ? void 0 : _o.baseSeverity) || (metric === null || metric === void 0 ? void 0 : metric.baseSeverity) || null,
            description: String(((_q = (_p = cve.descriptions) === null || _p === void 0 ? void 0 : _p.find((d) => d.lang === 'en')) === null || _q === void 0 ? void 0 : _q.value) || '').slice(0, 400),
            published: cve.published || null,
            url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        };
    }).filter((r) => r.id.startsWith('CVE-'));
    records.sort((a, b) => { var _a, _b; return ((_a = b.cvss) !== null && _a !== void 0 ? _a : 0) - ((_b = a.cvss) !== null && _b !== void 0 ? _b : 0); });
    return { fetchedAt: Date.now(), total: Number((_a = data === null || data === void 0 ? void 0 : data.totalResults) !== null && _a !== void 0 ? _a : records.length), records };
};
exports.parseNvdResponse = parseNvdResponse;
const lookupCves = (cpe, signal) => __awaiter(void 0, void 0, void 0, function* () {
    const hit = cache.get(cpe);
    if (hit && Date.now() - hit.fetchedAt < CACHE_TTL_MS)
        return Object.assign(Object.assign({}, hit), { cached: true });
    let lastError;
    for (let attempt = 0; attempt < 2; attempt += 1) {
        yield waitForSlot(signal);
        try {
            // isVulnerable is a flag parameter (no value), so it is appended manually.
            const res = yield axios_1.default.get(`${NVD_URL}?cpeName=${encodeURIComponent(cpe)}&isVulnerable&resultsPerPage=200`, {
                timeout: 30000,
                signal,
                maxContentLength: 20 * 1024 * 1024,
                headers: Object.assign({ 'User-Agent': 'RAKSHAK-VulnScanner/1.0' }, (process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {})),
            });
            const entry = (0, exports.parseNvdResponse)(res.data);
            cache.set(cpe, entry);
            return Object.assign(Object.assign({}, entry), { cached: false });
        }
        catch (err) {
            if (signal.aborted)
                throw new Error('CANCELLED');
            lastError = err;
            if ((err === null || err === void 0 ? void 0 : err.response) && err.response.status < 500 && err.response.status !== 429)
                break; // not retryable
        }
    }
    throw lastError;
});
exports.lookupCves = lookupCves;
const describeError = (err) => ((err === null || err === void 0 ? void 0 : err.response) ? `HTTP ${err.response.status}` : (err === null || err === void 0 ? void 0 : err.code) || (err === null || err === void 0 ? void 0 : err.message) || 'unknown error');
exports.cveCorrelationCheck = {
    id: 'cve-correlation',
    label: 'Known vulnerabilities (NVD CVE correlation)',
    phase: 'CVE Correlation',
    profiles: context_1.COMPREHENSIVE_ONLY,
    run(ctx) {
        var _a, _b, _c, _d;
        return __awaiter(this, void 0, void 0, function* () {
            const candidates = ctx.data.technologies.filter((t) => Boolean(t.cpe));
            if (!candidates.length) {
                return (0, context_1.skipped)('No technology with an explicit version and a known CPE identifier was detected, so no CVE lookup was possible.');
            }
            const findings = [];
            const failures = [];
            const checkedAt = new Date().toISOString();
            for (const tech of candidates.slice(0, 5)) {
                try {
                    const lookup = yield (0, exports.lookupCves)(tech.cpe, ctx.signal);
                    if (!lookup.total)
                        continue;
                    const top = lookup.records.slice(0, MAX_LISTED);
                    const maxCvss = (_b = (_a = top[0]) === null || _a === void 0 ? void 0 : _a.cvss) !== null && _b !== void 0 ? _b : null;
                    findings.push((0, findings_1.makeFinding)({
                        checkId: 'cve-correlation', key: tech.cpe,
                        title: `${tech.name} ${tech.version}: ${lookup.total} known CVE${lookup.total === 1 ? '' : 's'} for this version`,
                        category: 'Known Vulnerabilities (CVE)', owasp: 'A06:2021 Vulnerable and Outdated Components',
                        severity: severityFromCvss(maxCvss),
                        confidence: tech.confidence === 'high' ? 'medium' : 'low',
                        verification: 'potential',
                        description: `NVD lists ${lookup.total} CVE(s) whose affected-version ranges include ${tech.name} ${tech.version}. This is a version-based match: the detected version may be inaccurate, or fixes may have been backported (common in Linux distribution packages). Each CVE also requires specific modules or configurations, so exposure must be verified manually.`,
                        affected: ((_c = ctx.data.base) === null || _c === void 0 ? void 0 : _c.url) || ctx.target.url.href,
                        evidence: [
                            { label: 'Detected technology', value: `${tech.name} ${tech.version}` },
                            { label: 'Version evidence', value: tech.evidence },
                            { label: 'CPE queried', value: tech.cpe },
                            { label: 'Highest CVSS', value: maxCvss !== null ? String(maxCvss) : 'n/a' },
                            { label: 'Intelligence source', value: `NIST NVD CVE API 2.0${lookup.cached ? ' (cached)' : ''}` },
                            { label: 'Checked at', value: checkedAt },
                        ],
                        detection: 'CPE built from explicit version evidence; NVD queried with cpeName + isVulnerable (version ranges evaluated by NVD).',
                        impact: 'If the version is accurate and the affected component is enabled, attackers can use publicly documented exploits.',
                        remediation: `Upgrade ${tech.name} to the latest supported release, then re-scan. If you rely on distribution packages, confirm the patch level with your vendor’s security advisories.`,
                        references: [findings_1.REF.nvd, findings_1.REF.owaspA06],
                        cveId: (_d = top[0]) === null || _d === void 0 ? void 0 : _d.id,
                        cves: top,
                    }));
                }
                catch (err) {
                    if ((err === null || err === void 0 ? void 0 : err.message) === 'CANCELLED' || ctx.signal.aborted)
                        throw err;
                    failures.push(`${tech.name}: ${describeError(err)}`);
                }
            }
            if (failures.length && !findings.length)
                return (0, context_1.inconclusive)(`NVD lookup failed (${failures.join('; ')}). Other results are unaffected.`);
            return (0, context_1.result)(findings, `${candidates.length} versioned technolog${candidates.length === 1 ? 'y' : 'ies'} checked against NVD${failures.length ? `; failed: ${failures.join('; ')}` : ''}`);
        });
    },
};
