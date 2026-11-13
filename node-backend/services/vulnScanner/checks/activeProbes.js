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
exports.openRedirectCheck = exports.sqlInjectionCheck = exports.reflectedInputCheck = exports.reflectionContext = void 0;
const crypto_1 = __importDefault(require("crypto"));
const context_1 = require("../context");
const findings_1 = require("../findings");
const safeHttp_1 = require("../safeHttp");
/**
 * Safe, bounded active probes (standard + comprehensive). GET requests only,
 * changing query-string values; no request bodies, no destructive payloads, no
 * data extraction, at most MAX_PARAMS parameters per check.
 */
const MAX_PARAMS = 5;
const REDIRECT_PROBE = 'https://example.com/rakshak-redirect-probe';
const REDIRECT_PARAM_NAMES = ['next', 'url', 'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnurl', 'return_to', 'returnto', 'continue', 'dest', 'destination', 'goto', 'target', 'r', 'u'];
const withParam = (base, name, value) => {
    const url = new URL(base.href);
    url.searchParams.set(name, value);
    return url.href;
};
const targetParams = (url) => [...new Set([...url.searchParams.keys()])].slice(0, MAX_PARAMS);
/**
 * Parameter probes use the URL the user submitted, not the post-redirect URL:
 * a redirecting endpoint (e.g. /login?next=…) is exactly what must be tested.
 */
const probeUrl = (ctx) => new URL(ctx.target.url.href);
const rethrowCancel = (err) => {
    if (err instanceof safeHttp_1.ProbeError && (err.code === 'CANCELLED' || err.code === 'BUDGET'))
        throw err;
};
const reflectionContext = (body, marker, payload) => {
    const index = body.indexOf(payload);
    if (index === -1)
        return body.includes(marker) ? 'encoded' : null;
    const before = body.slice(Math.max(0, index - 2000), index);
    const lastScriptOpen = before.toLowerCase().lastIndexOf('<script');
    const lastScriptClose = before.toLowerCase().lastIndexOf('</script');
    if (lastScriptOpen > lastScriptClose)
        return 'script';
    const lastTagOpen = before.lastIndexOf('<');
    const lastTagClose = before.lastIndexOf('>');
    if (lastTagOpen > lastTagClose)
        return 'attribute';
    return 'html';
};
exports.reflectionContext = reflectionContext;
exports.reflectedInputCheck = {
    id: 'reflected-input',
    label: 'Reflected input (XSS indicators)',
    phase: 'Vulnerability Checks',
    profiles: context_1.STANDARD_UP,
    run(ctx) {
        return __awaiter(this, void 0, void 0, function* () {
            const base = ctx.data.base;
            if (!base)
                return (0, context_1.skipped)('No response available.');
            const pageUrl = probeUrl(ctx);
            const params = targetParams(pageUrl);
            if (!params.length)
                params.push('q'); // probe one generic search-style parameter
            const findings = [];
            let tested = 0;
            for (const name of params) {
                const marker = `rk${crypto_1.default.randomBytes(4).toString('hex')}`;
                const payload = `${marker}"'<rkx>`; // harmless: an unknown tag, never a script
                try {
                    const res = yield ctx.http.request(withParam(pageUrl, name, payload), { maxBytes: 512 * 1024 });
                    tested += 1;
                    if (!(0, safeHttp_1.isHtml)(res))
                        continue;
                    const context = (0, exports.reflectionContext)(res.body, marker, payload);
                    if (!context || context === 'encoded')
                        continue;
                    const at = res.body.indexOf(payload);
                    const snippet = res.body.slice(Math.max(0, at - 60), at + payload.length + 30).replace(/\s+/g, ' ');
                    findings.push((0, findings_1.makeFinding)({
                        checkId: 'reflected-input', key: `${pageUrl.pathname}|${name}`,
                        title: `Unencoded reflection of parameter "${name}" (${context} context)`,
                        category: 'Cross-Site Scripting', owasp: 'A03:2021 Injection',
                        severity: context === 'script' || context === 'html' ? 'medium' : 'low',
                        confidence: context === 'html' ? 'medium' : 'low',
                        verification: 'potential',
                        description: `The value of "${name}" is returned in the HTML ${context} context without encoding < > " '. This is a strong indicator of reflected XSS, but no script was executed to confirm exploitability.`,
                        affected: withParam(pageUrl, name, '…'),
                        evidence: [
                            { label: 'Probe value', value: payload },
                            { label: 'Reflection context', value: context },
                            { label: 'Response snippet', value: snippet },
                            { label: 'Content-Type', value: (0, safeHttp_1.header)(res, 'content-type') || '' },
                        ],
                        detection: 'Single GET request with a unique marker containing HTML special characters; response searched for the unencoded marker.',
                        impact: 'If exploitable, an attacker-crafted link could run JavaScript in the victim’s session (account takeover, data theft).',
                        remediation: 'Context-encode all output (HTML, attribute, JavaScript), validate input, and deploy a strict Content-Security-Policy.',
                        references: [{ title: 'OWASP XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }, findings_1.REF.owaspA03],
                    }));
                }
                catch (err) {
                    rethrowCancel(err);
                }
            }
            return (0, context_1.result)(findings, `${tested} parameter(s) probed`);
        });
    },
};
// ── SQL injection indicators (error-based, differential) ────────────────────
const SQL_ERRORS = [
    { db: 'MySQL/MariaDB', re: /(You have an error in your SQL syntax|check the manual that corresponds to your (MySQL|MariaDB) server version|Warning: mysqli?_|MySQLSyntaxErrorException)/i },
    { db: 'PostgreSQL', re: /(unterminated quoted string at or near|syntax error at or near "|PSQLException|pg_query\(\))/i },
    { db: 'Microsoft SQL Server', re: /(Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near)/i },
    { db: 'Oracle', re: /(ORA-0(0933|1756|0921)|quoted string not properly terminated)/i },
    { db: 'SQLite', re: /(SQLITE_ERROR|sqlite3\.OperationalError|unrecognized token: ")/i },
];
const sqlError = (body) => SQL_ERRORS.find((s) => s.re.test(body)) || null;
exports.sqlInjectionCheck = {
    id: 'sql-injection',
    label: 'SQL injection indicators (error-based)',
    phase: 'Vulnerability Checks',
    profiles: context_1.STANDARD_UP,
    run(ctx) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const base = ctx.data.base;
            if (!base)
                return (0, context_1.skipped)('No response available.');
            const pageUrl = probeUrl(ctx);
            const params = targetParams(pageUrl);
            if (!params.length)
                return (0, context_1.skipped)('The target URL has no query parameters to test. Scan a URL such as /products?id=1 to test parameters.');
            const findings = [];
            const genericErrors = [];
            for (const name of params) {
                const original = (_a = pageUrl.searchParams.get(name)) !== null && _a !== void 0 ? _a : '';
                try {
                    const baseline = yield ctx.http.request(withParam(pageUrl, name, original), { maxBytes: 256 * 1024 });
                    if (sqlError(baseline.body))
                        continue; // errors already present: cannot attribute them to the probe
                    const quoted = yield ctx.http.request(withParam(pageUrl, name, `${original}'`), { maxBytes: 256 * 1024 });
                    const first = sqlError(quoted.body);
                    if (!first) {
                        // A generic 5xx without a database message is NOT evidence of SQL injection.
                        if (quoted.status >= 500 && baseline.status < 500)
                            genericErrors.push(name);
                        continue;
                    }
                    // Differential + repeatability: a doubled quote (valid SQL escape) must NOT error,
                    // and the single quote must error again.
                    const escaped = yield ctx.http.request(withParam(pageUrl, name, `${original}''`), { maxBytes: 256 * 1024 });
                    const repeat = yield ctx.http.request(withParam(pageUrl, name, `${original}'`), { maxBytes: 256 * 1024 });
                    const repeated = sqlError(repeat.body);
                    const escapedClean = !sqlError(escaped.body);
                    if (!repeated)
                        continue;
                    findings.push((0, findings_1.makeFinding)({
                        checkId: 'sql-injection', key: `${pageUrl.pathname}|${name}`,
                        title: `Database error triggered by parameter "${name}" (possible SQL injection)`,
                        category: 'Injection', owasp: 'A03:2021 Injection',
                        severity: 'high', confidence: escapedClean ? 'high' : 'medium', verification: 'potential',
                        description: `Adding a single quote to "${name}" consistently produces a ${first.db} error message${escapedClean ? ', while a correctly escaped quote does not' : ''}. The input appears to be placed into a SQL query without parameterisation. No data was extracted and no further payloads were sent.`,
                        affected: withParam(pageUrl, name, '…'),
                        evidence: [
                            { label: 'Baseline value', value: `${name}=${original}` },
                            { label: 'Probe', value: `${name}=${original}'` },
                            { label: 'Database error signature', value: first.db },
                            { label: 'Repeated', value: 'yes (2/2 probes)' },
                            { label: "Escaped quote ('') produced error", value: escapedClean ? 'no' : 'yes' },
                        ],
                        detection: 'Four GET requests: baseline, single quote, escaped quote, single quote again. Only error messages were compared.',
                        impact: 'SQL injection can allow reading or modifying database contents and sometimes full server compromise.',
                        remediation: 'Use parameterised queries / prepared statements for every database call and disable detailed database errors in production.',
                        references: [{ title: 'OWASP SQL Injection Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' }, findings_1.REF.owaspA03],
                    }));
                }
                catch (err) {
                    rethrowCancel(err);
                }
            }
            const note = [
                `${params.length} parameter(s) tested for database error messages`,
                genericErrors.length ? `a quote caused a generic server error on ${genericErrors.join(', ')} (no database message, so not reported)` : '',
                'time-based/blind injection is not tested',
            ].filter(Boolean).join('; ');
            return (0, context_1.result)(findings, note);
        });
    },
};
// ── Open redirect ───────────────────────────────────────────────────────────
exports.openRedirectCheck = {
    id: 'open-redirect',
    label: 'Open redirect',
    phase: 'Vulnerability Checks',
    profiles: context_1.STANDARD_UP,
    run(ctx) {
        return __awaiter(this, void 0, void 0, function* () {
            const base = ctx.data.base;
            if (!base)
                return (0, context_1.skipped)('No response available.');
            const pageUrl = probeUrl(ctx);
            const fromUrl = targetParams(pageUrl).filter((n) => REDIRECT_PARAM_NAMES.includes(n.toLowerCase()) || /^(https?:)?\/\//.test(pageUrl.searchParams.get(n) || ''));
            const extra = ctx.profile === 'comprehensive' ? REDIRECT_PARAM_NAMES.slice(0, 10) : [];
            const params = [...new Set([...fromUrl, ...extra])];
            if (!params.length)
                return (0, context_1.skipped)('No redirect-style parameters in the URL (comprehensive profile also tests common names).');
            const findings = [];
            for (const name of params) {
                try {
                    const res = yield ctx.http.request(withParam(pageUrl, name, REDIRECT_PROBE), { maxRedirects: 0, readBody: false });
                    const location = (0, safeHttp_1.header)(res, 'location');
                    if (res.status < 300 || res.status >= 400 || !location)
                        continue;
                    let dest;
                    try {
                        dest = new URL(location, pageUrl);
                    }
                    catch (_a) {
                        continue;
                    }
                    if (dest.hostname !== 'example.com')
                        continue;
                    findings.push((0, findings_1.makeFinding)({
                        checkId: 'open-redirect', key: `${pageUrl.pathname}|${name}`,
                        title: `Open redirect via parameter "${name}"`,
                        category: 'Open Redirect', owasp: 'A01:2021 Broken Access Control',
                        severity: 'medium', confidence: 'high', verification: 'confirmed',
                        description: `The server redirects to an arbitrary external site supplied in "${name}".`,
                        affected: withParam(pageUrl, name, '…'),
                        evidence: [{ label: 'Probe', value: `${name}=${REDIRECT_PROBE}` }, { label: 'Response status', value: String(res.status) }, { label: 'Location', value: location }],
                        detection: 'GET request with an external test destination (example.com); the redirect was not followed.',
                        impact: 'Attackers can craft links on your trusted domain that forward victims to phishing pages, and it can help steal OAuth tokens.',
                        remediation: 'Only redirect to relative paths or an allow-list of trusted hosts; reject absolute external URLs.',
                        references: [{ title: 'OWASP Unvalidated Redirects Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' }],
                    }));
                }
                catch (err) {
                    rethrowCancel(err);
                }
            }
            return (0, context_1.result)(findings, `${params.length} parameter(s) tested`);
        });
    },
};
