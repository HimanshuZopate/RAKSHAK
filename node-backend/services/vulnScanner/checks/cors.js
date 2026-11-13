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
exports.corsCheck = void 0;
const context_1 = require("../context");
const findings_1 = require("../findings");
const safeHttp_1 = require("../safeHttp");
/**
 * CORS configuration analysis (all profiles).
 * Sends harmless GET/OPTIONS requests carrying controlled Origin values that
 * point to a reserved, non-resolvable domain (.invalid, RFC 2606).
 */
const PROBE_ORIGIN = 'https://rakshak-cors-probe.invalid';
exports.corsCheck = {
    id: 'cors',
    label: 'CORS configuration',
    phase: 'CORS',
    profiles: context_1.ALL_PROFILES,
    run(ctx) {
        return __awaiter(this, void 0, void 0, function* () {
            const base = ctx.data.base;
            if (!base)
                return (0, context_1.inconclusive)('No response available to analyse.');
            const url = base.url;
            const findings = [];
            const add = (f) => findings.push((0, findings_1.makeFinding)(f));
            const common = { checkId: 'cors', category: 'CORS', owasp: 'A05:2021 Security Misconfiguration', affected: url, references: [findings_1.REF.mdnCors] };
            const summarize = (res, origin) => [
                { label: 'Request Origin', value: origin },
                { label: 'Access-Control-Allow-Origin', value: (0, safeHttp_1.header)(res, 'access-control-allow-origin') || '(not present)' },
                { label: 'Access-Control-Allow-Credentials', value: (0, safeHttp_1.header)(res, 'access-control-allow-credentials') || '(not present)' },
            ];
            const probe = yield ctx.http.request(url, { headers: { Origin: PROBE_ORIGIN }, maxBytes: 8 * 1024 });
            const acao = ((0, safeHttp_1.header)(probe, 'access-control-allow-origin') || '').trim();
            const credentials = ((0, safeHttp_1.header)(probe, 'access-control-allow-credentials') || '').trim().toLowerCase() === 'true';
            if (acao === PROBE_ORIGIN) {
                add(Object.assign(Object.assign({}, common), { key: 'reflected-origin', title: credentials ? 'CORS reflects any origin and allows credentials' : 'CORS reflects arbitrary origins', severity: credentials ? 'high' : 'low', confidence: 'high', verification: 'confirmed', description: credentials
                        ? 'The server copied an untrusted Origin into Access-Control-Allow-Origin and allows credentials. Any website can make authenticated requests and read the responses.'
                        : 'The server copies the request Origin into Access-Control-Allow-Origin without credentials. Other sites can read this response, but not with the user’s cookies.', evidence: summarize(probe, PROBE_ORIGIN), detection: `GET request with Origin: ${PROBE_ORIGIN} (an unregistrable test domain).`, impact: credentials
                        ? 'A malicious website could read data that is visible to the logged-in user (account details, tokens, private API data).'
                        : 'Only publicly readable data is exposed cross-origin; risk depends on what this endpoint returns.', remediation: 'Validate the Origin against an explicit allow-list of trusted origins and only enable credentials for those origins.' }));
            }
            else if (acao === '*') {
                add(Object.assign(Object.assign({}, common), { key: 'wildcard', title: credentials ? 'CORS wildcard combined with credentials (invalid configuration)' : 'CORS allows any origin (wildcard)', severity: credentials ? 'low' : 'info', confidence: 'high', verification: credentials ? 'misconfiguration' : 'informational', description: credentials
                        ? 'Access-Control-Allow-Origin: * is sent together with Allow-Credentials: true. Browsers reject this combination, which indicates a misunderstood configuration.'
                        : 'Any website may read this response, but browsers never attach cookies to wildcard CORS requests. This is normal for public resources.', evidence: summarize(probe, PROBE_ORIGIN), detection: `GET request with Origin: ${PROBE_ORIGIN}.`, impact: 'Wildcard CORS does not expose authenticated data by itself; review whether the endpoint returns anything non-public.', remediation: 'Use an explicit origin allow-list for anything that is not intentionally public.' }));
            }
            // "null" origin (sandboxed iframes, file://) — only meaningful with credentials.
            const nullProbe = yield ctx.http.request(url, { headers: { Origin: 'null' }, maxBytes: 8 * 1024 });
            if (((0, safeHttp_1.header)(nullProbe, 'access-control-allow-origin') || '').trim() === 'null' &&
                ((0, safeHttp_1.header)(nullProbe, 'access-control-allow-credentials') || '').toLowerCase() === 'true') {
                add(Object.assign(Object.assign({}, common), { key: 'null-origin', title: 'CORS trusts the "null" origin with credentials', severity: 'high', confidence: 'high', verification: 'confirmed', description: 'The server allows Origin: null with credentials. Any attacker page can obtain a null origin through a sandboxed iframe.', evidence: summarize(nullProbe, 'null'), detection: 'GET request with Origin: null.', impact: 'Attacker-controlled pages can make authenticated requests and read the responses.', remediation: 'Never allow the "null" origin; use an explicit allow-list.' }));
            }
            // Preflight behaviour for a state-changing method (OPTIONS only; nothing is modified).
            const preflight = yield ctx.http.request(url, {
                method: 'OPTIONS',
                headers: { Origin: PROBE_ORIGIN, 'Access-Control-Request-Method': 'DELETE', 'Access-Control-Request-Headers': 'content-type' },
            });
            const pfOrigin = ((0, safeHttp_1.header)(preflight, 'access-control-allow-origin') || '').trim();
            const pfMethods = ((0, safeHttp_1.header)(preflight, 'access-control-allow-methods') || '').toUpperCase();
            if ((pfOrigin === PROBE_ORIGIN || pfOrigin === '*') && /\b(DELETE|PUT|PATCH)\b/.test(pfMethods)) {
                add(Object.assign(Object.assign({}, common), { key: 'preflight-permissive', title: 'CORS preflight approves state-changing methods for untrusted origins', severity: pfOrigin === PROBE_ORIGIN && credentials ? 'medium' : 'low', confidence: 'medium', verification: 'potential', description: `An OPTIONS preflight from an untrusted origin was answered with Access-Control-Allow-Methods: ${pfMethods}. Whether these methods actually change data has not been tested.`, evidence: [
                        { label: 'Preflight Origin', value: PROBE_ORIGIN },
                        { label: 'Access-Control-Request-Method', value: 'DELETE' },
                        { label: 'Access-Control-Allow-Origin', value: pfOrigin },
                        { label: 'Access-Control-Allow-Methods', value: pfMethods },
                    ], detection: 'OPTIONS preflight request (no DELETE/PUT request was sent).', impact: 'Cross-site scripts may be able to invoke modifying API calls if the endpoint supports them.', remediation: 'Only return permissive preflight responses for trusted origins and only list methods that origin needs.' }));
            }
            return (0, context_1.result)(findings, acao ? `Access-Control-Allow-Origin: ${acao}` : 'No CORS headers returned to an untrusted origin');
        });
    },
};
