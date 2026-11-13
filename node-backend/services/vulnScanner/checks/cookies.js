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
Object.defineProperty(exports, "__esModule", { value: true });
exports.cookiesCheck = exports.parseSetCookie = void 0;
const context_1 = require("../context");
const findings_1 = require("../findings");
const parseSetCookie = (raw) => {
    const [pair, ...attrs] = raw.split(';');
    const eq = pair.indexOf('=');
    const name = (eq >= 0 ? pair.slice(0, eq) : pair).trim();
    if (!name)
        return null;
    const cookie = { name, secure: false, httpOnly: false, sameSite: null, domain: null, path: null, maxAgeSeconds: null, expires: null, attributeSummary: '' };
    const kept = [];
    for (const attr of attrs) {
        const [k, ...rest] = attr.trim().split('=');
        const key = k.trim().toLowerCase();
        const value = rest.join('=').trim();
        if (!key)
            continue;
        if (key === 'secure')
            cookie.secure = true;
        else if (key === 'httponly')
            cookie.httpOnly = true;
        else if (key === 'samesite')
            cookie.sameSite = value.toLowerCase() || null;
        else if (key === 'domain')
            cookie.domain = value.toLowerCase();
        else if (key === 'path')
            cookie.path = value;
        else if (key === 'max-age')
            cookie.maxAgeSeconds = Number.isFinite(Number(value)) ? Number(value) : null;
        else if (key === 'expires') {
            const date = new Date(value);
            cookie.expires = Number.isNaN(date.getTime()) ? null : date;
        }
        kept.push(value ? `${k.trim()}=${value}` : k.trim());
    }
    cookie.attributeSummary = `${name}=<redacted>${kept.length ? `; ${kept.join('; ')}` : ''}`;
    return cookie;
};
exports.parseSetCookie = parseSetCookie;
const SESSION_LIKE = /(sess|sid|auth|token|jwt|login|remember|identity|csrf|xsrf|account|user)/i;
exports.cookiesCheck = {
    id: 'cookies',
    label: 'Cookie security attributes',
    phase: 'Cookies',
    profiles: context_1.ALL_PROFILES,
    run(ctx) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const base = ctx.data.base;
            if (!base)
                return (0, context_1.inconclusive)('No response available to analyse.');
            const raw = [...base.setCookies];
            const cookies = raw.map(exports.parseSetCookie).filter((c) => Boolean(c));
            if (!cookies.length)
                return (0, context_1.result)([], 'No cookies were set by the target page.');
            const https = base.url.startsWith('https:');
            const host = new URL(base.url).hostname;
            const findings = [];
            for (const cookie of cookies) {
                const sessionLike = SESSION_LIKE.test(cookie.name);
                const issues = [];
                const lifetimeSeconds = (_a = cookie.maxAgeSeconds) !== null && _a !== void 0 ? _a : (cookie.expires ? (cookie.expires.getTime() - Date.now()) / 1000 : null);
                if (https && !cookie.secure)
                    issues.push({ text: 'missing Secure (can be sent over plain HTTP)', severity: sessionLike ? 'medium' : 'low' });
                if (!cookie.httpOnly)
                    issues.push({ text: 'missing HttpOnly (readable by JavaScript, e.g. after XSS)', severity: sessionLike ? 'medium' : 'info' });
                if (!cookie.sameSite)
                    issues.push({ text: 'no SameSite attribute (browsers default to Lax)', severity: sessionLike ? 'low' : 'info' });
                else if (cookie.sameSite === 'none' && !cookie.secure)
                    issues.push({ text: 'SameSite=None without Secure (rejected by modern browsers)', severity: 'low' });
                if (sessionLike && lifetimeSeconds !== null && lifetimeSeconds > 30 * 86400) {
                    issues.push({ text: `long-lived (${Math.round(lifetimeSeconds / 86400)} days) for a session-like cookie`, severity: 'low' });
                }
                if (cookie.domain && cookie.domain.replace(/^\./, '') !== host) {
                    issues.push({ text: `scoped to parent domain ${cookie.domain} (shared with all subdomains)`, severity: 'info' });
                }
                if (cookie.name.startsWith('__Host-') && (!cookie.secure || cookie.domain || cookie.path !== '/')) {
                    issues.push({ text: '__Host- prefix requirements not met (Secure, no Domain, Path=/)', severity: 'low' });
                }
                if (cookie.name.startsWith('__Secure-') && !cookie.secure)
                    issues.push({ text: '__Secure- prefix without Secure', severity: 'low' });
                if (!issues.length)
                    continue;
                const order = ['critical', 'high', 'medium', 'low', 'info'];
                const severity = order.find((s) => issues.some((i) => i.severity === s));
                findings.push((0, findings_1.makeFinding)({
                    checkId: 'cookies',
                    key: cookie.name,
                    title: `Cookie "${cookie.name}" is missing security attributes`,
                    category: 'Cookie Security',
                    owasp: 'A05:2021 Security Misconfiguration',
                    severity,
                    confidence: sessionLike ? 'medium' : 'high',
                    verification: severity === 'info' ? 'informational' : 'misconfiguration',
                    description: `Weaknesses: ${issues.map((i) => i.text).join('; ')}.${sessionLike ? ' The name suggests it may be session or authentication related; the name alone does not prove its purpose.' : ''}`,
                    affected: base.url,
                    evidence: [{ label: 'Set-Cookie (value redacted)', value: cookie.attributeSummary }, ...issues.map((i) => ({ label: `Issue (${i.severity})`, value: i.text }))],
                    detection: 'Parsed the Set-Cookie headers of the target response. Cookie values are not stored.',
                    impact: 'Missing attributes make cookies easier to steal (network interception, XSS) or to send in cross-site requests (CSRF).',
                    remediation: 'Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies, and keep their lifetime short.',
                    references: [findings_1.REF.mdnCookies],
                }));
            }
            return (0, context_1.result)(findings, `${cookies.length} cookie(s) analysed`);
        });
    },
};
