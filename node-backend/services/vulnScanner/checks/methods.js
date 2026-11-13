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
exports.methodsCheck = void 0;
const context_1 = require("../context");
const findings_1 = require("../findings");
const safeHttp_1 = require("../safeHttp");
/**
 * HTTP method analysis (standard + comprehensive).
 * OPTIONS reveals advertised methods; TRACE is sent without a body to see whether
 * the server echoes requests. PUT/DELETE/PATCH are never sent.
 */
exports.methodsCheck = {
    id: 'http-methods',
    label: 'HTTP method exposure',
    phase: 'HTTP Methods',
    profiles: context_1.STANDARD_UP,
    run(ctx) {
        return __awaiter(this, void 0, void 0, function* () {
            const base = ctx.data.base;
            if (!base)
                return (0, context_1.inconclusive)('No response available.');
            const url = base.url;
            const findings = [];
            const options = yield ctx.http.request(url, { method: 'OPTIONS' });
            const allow = ((0, safeHttp_1.header)(options, 'allow') || (0, safeHttp_1.header)(options, 'access-control-allow-methods') || '').toUpperCase();
            const advertised = allow.split(',').map((m) => m.trim()).filter(Boolean);
            const risky = advertised.filter((m) => ['PUT', 'DELETE', 'PATCH', 'CONNECT', 'PROPFIND', 'MKCOL', 'MOVE', 'COPY'].includes(m));
            if (risky.length) {
                findings.push((0, findings_1.makeFinding)({
                    checkId: 'http-methods', key: 'risky-advertised', title: `Server advertises state-changing methods (${risky.join(', ')})`,
                    category: 'HTTP Methods', owasp: 'A05:2021 Security Misconfiguration', severity: 'low', confidence: 'low', verification: 'potential',
                    description: 'The OPTIONS response lists methods that can modify server resources. An advertised method is not proof that it is enabled or unprotected; these methods were not tested.',
                    affected: url, evidence: [{ label: 'OPTIONS status', value: String(options.status) }, { label: 'Allow', value: allow }],
                    detection: 'OPTIONS request; PUT/DELETE were deliberately NOT sent.',
                    impact: 'If these methods are really enabled without authorisation, files or data could be modified (e.g. WebDAV uploads).',
                    remediation: 'Disable unused methods at the web server and require authentication for any method that changes state.',
                    references: [findings_1.REF.owaspA05],
                }));
            }
            let traceEnabled = false;
            try {
                const trace = yield ctx.http.request(url, { method: 'TRACE', maxBytes: 8 * 1024 });
                const ct = (0, safeHttp_1.header)(trace, 'content-type') || '';
                traceEnabled = trace.status === 200 && (/message\/http/i.test(ct) || /^TRACE \/\S* HTTP\/1\.[01]/m.test(trace.body));
                if (traceEnabled) {
                    findings.push((0, findings_1.makeFinding)({
                        checkId: 'http-methods', key: 'trace', title: 'HTTP TRACE method is enabled', category: 'HTTP Methods', owasp: 'A05:2021 Security Misconfiguration',
                        severity: 'low', confidence: 'high', verification: 'confirmed',
                        description: 'The server answered a TRACE request by echoing the request back.',
                        affected: url, evidence: [{ label: 'TRACE status', value: String(trace.status) }, { label: 'Content-Type', value: ct || '(none)' }, { label: 'Echoed request line', value: (trace.body.match(/^TRACE \S+ HTTP\/1\.[01]/m) || [''])[0] }],
                        detection: 'Single TRACE request without a body.',
                        impact: 'Mostly a legacy risk (Cross-Site Tracing); modern browsers block TRACE, but echoing requests can leak headers added by proxies.',
                        remediation: 'Disable TRACE (Apache: TraceEnable off; nginx and most frameworks reject it by default).',
                        references: [findings_1.REF.owaspA05],
                    }));
                }
            }
            catch (_a) {
                // A refused TRACE request is the secure outcome.
            }
            return (0, context_1.result)(findings, `Allow: ${allow || 'not advertised'} · TRACE ${traceEnabled ? 'enabled' : 'not echoed'}`);
        });
    },
};
