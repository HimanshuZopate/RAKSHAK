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
exports.connectivityCheck = void 0;
const context_1 = require("../context");
const findings_1 = require("../findings");
const safeHttp_1 = require("../safeHttp");
/**
 * Connectivity & transport check (all profiles, critical):
 *  1. GET the target (following up to 5 validated redirects) — this response is
 *     the baseline every later check analyses.
 *  2. Determine whether HTTPS is available and whether plain HTTP redirects to it.
 */
exports.connectivityCheck = {
    id: 'connectivity',
    label: 'Target connectivity & HTTPS enforcement',
    phase: 'Connectivity',
    profiles: context_1.ALL_PROFILES,
    critical: true,
    run(ctx) {
        return __awaiter(this, void 0, void 0, function* () {
            const { target, http, data } = ctx;
            const findings = [];
            data.base = yield http.request(target.url.href, { maxRedirects: 5, maxBytes: 1024 * 1024, timeoutMs: 12000 });
            const finalUrl = new URL(data.base.url);
            // HTTPS availability (if the final page is not already HTTPS).
            if (finalUrl.protocol === 'https:') {
                data.httpsAvailable = true;
            }
            else {
                try {
                    const httpsUrl = new URL(finalUrl.href);
                    httpsUrl.protocol = 'https:';
                    if (!target.isLab)
                        httpsUrl.port = '';
                    yield http.request(httpsUrl.href, { method: 'HEAD', timeoutMs: 8000 });
                    data.httpsAvailable = true;
                }
                catch (err) {
                    if (err instanceof safeHttp_1.ProbeError && err.code === 'CANCELLED')
                        throw err;
                    data.httpsAvailable = false;
                }
            }
            // Does plain HTTP redirect to HTTPS?
            if (data.httpsAvailable && !target.isLab) {
                try {
                    const plain = new URL(`http://${target.url.host}${target.url.pathname}`);
                    plain.port = '';
                    const res = yield http.request(plain.href, { method: 'GET', maxRedirects: 3, maxBytes: 16 * 1024, timeoutMs: 8000 });
                    data.httpRedirectsToHttps = new URL(res.url).protocol === 'https:';
                }
                catch (err) {
                    if (err instanceof safeHttp_1.ProbeError && err.code === 'CANCELLED')
                        throw err;
                    data.httpRedirectsToHttps = null; // port 80 closed/filtered: nothing to enforce, not a finding
                }
            }
            else {
                data.httpRedirectsToHttps = null;
            }
            const redirectEvidence = data.base.redirects.map((r, i) => ({ label: `Redirect ${i + 1} (${r.status})`, value: `${r.url} → ${r.location}` }));
            if (!data.httpsAvailable) {
                findings.push((0, findings_1.makeFinding)({
                    checkId: 'connectivity',
                    key: 'no-https',
                    title: 'Website is not available over HTTPS',
                    category: 'Transport Security',
                    owasp: 'A02:2021 Cryptographic Failures',
                    severity: 'high',
                    confidence: 'high',
                    verification: 'misconfiguration',
                    description: 'The site is served over plain HTTP and an HTTPS connection to the same host could not be established.',
                    affected: finalUrl.origin,
                    evidence: [{ label: 'Final URL', value: data.base.url }, { label: 'HTTPS probe', value: 'Connection failed or refused' }, ...redirectEvidence],
                    detection: 'GET request to the target followed by a HEAD request to the same host over HTTPS.',
                    impact: 'All traffic, including any credentials or session cookies, can be read or modified by anyone on the network path.',
                    remediation: 'Obtain a TLS certificate (for example from Let’s Encrypt), serve the site over HTTPS and redirect all HTTP requests to HTTPS.',
                    references: [findings_1.REF.owaspTlsCheat, findings_1.REF.owaspA02],
                }));
            }
            else if (finalUrl.protocol === 'http:') {
                findings.push((0, findings_1.makeFinding)({
                    checkId: 'connectivity',
                    key: 'served-over-http',
                    title: 'Page is served over HTTP although HTTPS is available',
                    category: 'Transport Security',
                    owasp: 'A02:2021 Cryptographic Failures',
                    severity: 'medium',
                    confidence: 'high',
                    verification: 'misconfiguration',
                    description: 'The requested page was delivered over plain HTTP and did not redirect to HTTPS, even though the host accepts HTTPS connections.',
                    affected: data.base.url,
                    evidence: [{ label: 'Final URL', value: data.base.url }, ...redirectEvidence],
                    detection: 'GET request to the target URL, following redirects.',
                    impact: 'Visitors who open the HTTP address use an unencrypted connection that can be intercepted or modified.',
                    remediation: 'Redirect every HTTP request to HTTPS with a 301 redirect and enable HSTS.',
                    references: [findings_1.REF.owaspTlsCheat],
                }));
            }
            else if (data.httpRedirectsToHttps === false) {
                findings.push((0, findings_1.makeFinding)({
                    checkId: 'connectivity',
                    key: 'http-no-redirect',
                    title: 'HTTP version of the site does not redirect to HTTPS',
                    category: 'Transport Security',
                    owasp: 'A02:2021 Cryptographic Failures',
                    severity: 'medium',
                    confidence: 'high',
                    verification: 'misconfiguration',
                    description: 'A request to the plain HTTP address was answered without redirecting to HTTPS.',
                    affected: `http://${target.url.host}/`,
                    evidence: [{ label: 'HTTP request', value: `http://${target.url.host}${target.url.pathname}` }, { label: 'Result', value: 'Served over HTTP (no redirect to https://)' }],
                    detection: 'GET request to the http:// version of the target, following up to 3 redirects.',
                    impact: 'Users who type the address without https:// or follow old links get an unencrypted connection.',
                    remediation: 'Configure the web server to answer all port-80 requests with a 301 redirect to the https:// URL.',
                    references: [findings_1.REF.owaspTlsCheat],
                }));
            }
            const note = `HTTP ${data.base.status} from ${data.base.url}${data.base.redirects.length ? ` after ${data.base.redirects.length} redirect(s)` : ''}`;
            return (0, context_1.result)(findings, note);
        });
    },
};
