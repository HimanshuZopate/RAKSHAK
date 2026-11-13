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
exports.tlsCheck = void 0;
const tls_1 = __importDefault(require("tls"));
const context_1 = require("../context");
const findings_1 = require("../findings");
const targetGuard_1 = require("../targetGuard");
/**
 * TLS / certificate analysis (all profiles).
 *
 * Trust errors are classified so that genuine target misconfigurations are not
 * confused with local trust-store limitations:
 *  - expired / not yet valid / hostname mismatch / self-signed → target problem (confirmed)
 *  - "unable to get local issuer" style errors → usually a missing intermediate on
 *    the server, but can be the scanner's trust store → reported as *potential*.
 */
const TARGET_TRUST_ERRORS = new Set(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_REVOKED', 'CERT_SIGNATURE_FAILURE', 'CERT_UNTRUSTED']);
const CHAIN_ERRORS = new Set(['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE']);
const PROTOCOLS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const handshake = (address, family, servername, port, signal, version) => new Promise((resolve, reject) => {
    // `address` is the already-validated IP literal, so no DNS lookup happens here.
    const socket = tls_1.default.connect(Object.assign({ host: address, port,
        servername, rejectUnauthorized: false, timeout: 8000 }, (version ? { minVersion: version, maxVersion: version, ciphers: 'DEFAULT@SECLEVEL=0' } : {})));
    const onAbort = () => { socket.destroy(); reject(new Error('CANCELLED')); };
    signal.addEventListener('abort', onAbort, { once: true });
    const done = (fn) => { signal.removeEventListener('abort', onAbort); fn(); socket.destroy(); };
    socket.once('secureConnect', () => {
        // authorizationError may be a code string ("CERT_HAS_EXPIRED") or an Error with .code.
        const authError = socket.authorizationError;
        done(() => {
            var _a, _b;
            return resolve({
                protocol: socket.getProtocol(),
                cipher: (_b = (_a = socket.getCipher()) === null || _a === void 0 ? void 0 : _a.name) !== null && _b !== void 0 ? _b : null,
                authorized: socket.authorized,
                authorizationError: authError ? String(authError.code || authError) : null,
                cert: socket.getPeerCertificate(true) || null,
            });
        });
    });
    socket.once('timeout', () => done(() => reject(Object.assign(new Error('TIMEOUT'), { code: 'TIMEOUT' }))));
    socket.once('error', (err) => done(() => reject(err)));
});
const nameOf = (entity) => {
    if (!entity)
        return null;
    return [entity.CN, entity.O].filter(Boolean).join(' / ') || null;
};
exports.tlsCheck = {
    id: 'tls',
    label: 'TLS certificate & protocol support',
    phase: 'TLS',
    profiles: context_1.ALL_PROFILES,
    run(ctx) {
        var _a, _b, _c, _d, _e, _f;
        return __awaiter(this, void 0, void 0, function* () {
            const { target, signal, data } = ctx;
            if (!data.httpsAvailable)
                return (0, context_1.skipped)('HTTPS is not available on this host.');
            const finalUrl = new URL(((_a = data.base) === null || _a === void 0 ? void 0 : _a.url) || target.url.href);
            const hostname = finalUrl.protocol === 'https:' ? finalUrl.hostname : target.hostname;
            const port = finalUrl.protocol === 'https:' ? Number(finalUrl.port || 443) : 443;
            const pinned = yield (0, targetGuard_1.resolveAllowedAddress)(hostname, port);
            ctx.http.requestCount += 1;
            let main;
            try {
                main = yield handshake(pinned.address, pinned.family, hostname, port, signal);
            }
            catch (err) {
                if ((err === null || err === void 0 ? void 0 : err.message) === 'CANCELLED')
                    throw err;
                return (0, context_1.inconclusive)(`TLS handshake failed: ${(err === null || err === void 0 ? void 0 : err.code) || (err === null || err === void 0 ? void 0 : err.message) || 'unknown error'}`);
            }
            const findings = [];
            const cert = main.cert && Object.keys(main.cert).length ? main.cert : null;
            const affected = `https://${hostname}${port === 443 ? '' : `:${port}`}`;
            const identityError = cert ? tls_1.default.checkServerIdentity(hostname, cert) : new Error('No certificate');
            const validTo = (cert === null || cert === void 0 ? void 0 : cert.valid_to) ? new Date(cert.valid_to) : null;
            const validFrom = (cert === null || cert === void 0 ? void 0 : cert.valid_from) ? new Date(cert.valid_from) : null;
            const daysRemaining = validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null;
            // Protocol support probes (sequential, 4 small handshakes).
            const supportedProtocols = {};
            for (const version of PROTOCOLS) {
                ctx.http.requestCount += 1;
                try {
                    const res = yield handshake(pinned.address, pinned.family, hostname, port, signal, version);
                    supportedProtocols[version] = res.protocol === version ? 'supported' : 'not supported';
                }
                catch (err) {
                    if ((err === null || err === void 0 ? void 0 : err.message) === 'CANCELLED')
                        throw err;
                    const code = String((err === null || err === void 0 ? void 0 : err.code) || '');
                    // Server refused the version (alert / reset / version mismatch) → not supported.
                    supportedProtocols[version] = code === 'TIMEOUT' ? 'inconclusive' : 'not supported';
                }
            }
            data.tls = {
                available: true,
                negotiatedProtocol: main.protocol,
                cipher: main.cipher,
                supportedProtocols,
                certificate: cert
                    ? {
                        subject: nameOf(cert.subject),
                        issuer: nameOf(cert.issuer),
                        subjectAltNames: String(cert.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean).slice(0, 25),
                        validFrom: (_b = validFrom === null || validFrom === void 0 ? void 0 : validFrom.toISOString()) !== null && _b !== void 0 ? _b : null,
                        validTo: (_c = validTo === null || validTo === void 0 ? void 0 : validTo.toISOString()) !== null && _c !== void 0 ? _c : null,
                        daysRemaining,
                        fingerprint256: cert.fingerprint256 || null,
                        trusted: main.authorized,
                        trustError: main.authorizationError,
                        hostnameMatches: !identityError,
                    }
                    : null,
            };
            const certEvidence = [
                { label: 'Subject', value: nameOf(cert === null || cert === void 0 ? void 0 : cert.subject) || 'unknown' },
                { label: 'Issuer', value: nameOf(cert === null || cert === void 0 ? void 0 : cert.issuer) || 'unknown' },
                { label: 'Valid', value: `${(_d = validFrom === null || validFrom === void 0 ? void 0 : validFrom.toISOString().slice(0, 10)) !== null && _d !== void 0 ? _d : '?'} → ${(_e = validTo === null || validTo === void 0 ? void 0 : validTo.toISOString().slice(0, 10)) !== null && _e !== void 0 ? _e : '?'}` },
                { label: 'Verification result', value: main.authorizationError || 'trusted' },
            ];
            const base = { checkId: 'tls', category: 'Transport Security', owasp: 'A02:2021 Cryptographic Failures', affected, references: [findings_1.REF.owaspTlsCheat, findings_1.REF.owaspA02] };
            const err = main.authorizationError || '';
            if (err === 'CERT_HAS_EXPIRED' || (daysRemaining !== null && daysRemaining < 0)) {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'expired', title: 'TLS certificate has expired', severity: 'high', confidence: 'high', verification: 'confirmed', description: `The certificate expired on ${validTo === null || validTo === void 0 ? void 0 : validTo.toUTCString()}.`, evidence: certEvidence, detection: 'TLS handshake and certificate inspection.', impact: 'Browsers show a full-page security warning; users who click through are exposed to interception.', remediation: 'Renew the certificate and automate renewal (e.g. ACME / Let’s Encrypt).' })));
            }
            else if (err === 'CERT_NOT_YET_VALID') {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'not-yet-valid', title: 'TLS certificate is not yet valid', severity: 'high', confidence: 'high', verification: 'confirmed', description: `The certificate only becomes valid on ${validFrom === null || validFrom === void 0 ? void 0 : validFrom.toUTCString()}.`, evidence: certEvidence, detection: 'TLS handshake and certificate inspection.', impact: 'Browsers reject the connection.', remediation: 'Install a currently valid certificate and check the server clock.' })));
            }
            if (identityError) {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'hostname-mismatch', title: 'TLS certificate does not match the hostname', severity: 'high', confidence: 'high', verification: 'confirmed', description: `The certificate is not valid for ${hostname}.`, evidence: [...certEvidence, { label: 'Subject alternative names', value: ((_f = data.tls.certificate) === null || _f === void 0 ? void 0 : _f.subjectAltNames.join(', ')) || 'none' }], detection: 'Verified the certificate against the hostname with Node.js tls.checkServerIdentity().', impact: 'Browsers show a security warning and the connection cannot be trusted.', remediation: `Issue a certificate whose subject alternative names include ${hostname}.` })));
            }
            if (err === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err === 'SELF_SIGNED_CERT_IN_CHAIN') {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'self-signed', title: 'Certificate is self-signed or chains to an untrusted root', severity: 'high', confidence: 'high', verification: 'confirmed', description: 'The certificate (or its root) is self-signed and not issued by a publicly trusted certificate authority.', evidence: certEvidence, detection: 'TLS handshake; chain verified against the Node.js/Mozilla root store.', impact: 'Browsers warn users; users who accept the warning can be intercepted by anyone presenting another self-signed certificate.', remediation: 'Use a certificate from a publicly trusted CA.' })));
            }
            else if (CHAIN_ERRORS.has(err)) {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'chain-incomplete', title: 'Certificate chain could not be verified', severity: 'medium', confidence: 'medium', verification: 'potential', description: `The scanner could not build a trusted chain (${err}). This usually means the server does not send its intermediate certificate, but it can also be caused by the scanner’s trust store.`, evidence: certEvidence, detection: 'TLS handshake; chain verified against the Node.js/Mozilla root store.', impact: 'Some clients (mobile apps, API clients, older browsers) will refuse to connect.', remediation: 'Configure the server to send the full certificate chain (leaf + intermediates) and re-test with an external TLS checker.' })));
            }
            else if (err && !TARGET_TRUST_ERRORS.has(err) && err !== 'ERR_TLS_CERT_ALTNAME_INVALID') {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'trust-other', title: 'Certificate could not be validated', severity: 'medium', confidence: 'low', verification: 'inconclusive', description: `Certificate validation returned ${err}.`, evidence: certEvidence, detection: 'TLS handshake and certificate validation.', impact: 'Clients may refuse the connection.', remediation: 'Verify the certificate chain with an external TLS checker.' })));
            }
            if (daysRemaining !== null && daysRemaining >= 0 && daysRemaining <= 30) {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'expiring', title: `TLS certificate expires in ${daysRemaining} day(s)`, severity: daysRemaining <= 7 ? 'medium' : 'low', confidence: 'high', verification: 'misconfiguration', description: `The certificate expires on ${validTo === null || validTo === void 0 ? void 0 : validTo.toUTCString()}.`, evidence: certEvidence, detection: 'Certificate validity inspection.', impact: 'The site will show security warnings once the certificate expires.', remediation: 'Renew the certificate now and automate renewal.' })));
            }
            const legacy = ['TLSv1', 'TLSv1.1'].filter((v) => supportedProtocols[v] === 'supported');
            if (legacy.length) {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'legacy-protocols', title: `Deprecated TLS versions accepted (${legacy.join(', ')})`, severity: 'medium', confidence: 'high', verification: 'confirmed', description: `The server completed handshakes using ${legacy.join(' and ')}, which were deprecated by RFC 8996 (2021).`, evidence: PROTOCOLS.map((v) => ({ label: v, value: supportedProtocols[v] })), detection: 'Separate TLS handshakes pinned to each protocol version (client allowed legacy versions for the probe only).', impact: 'Legacy protocols lack modern protections and enable downgrade-style attacks against old clients.', remediation: 'Disable TLS 1.0 and 1.1; allow only TLS 1.2 and TLS 1.3.' })));
            }
            if (supportedProtocols['TLSv1.3'] === 'not supported') {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'no-tls13', title: 'TLS 1.3 is not supported', severity: 'info', confidence: 'high', verification: 'informational', description: 'The server does not negotiate TLS 1.3.', evidence: PROTOCOLS.map((v) => ({ label: v, value: supportedProtocols[v] })), detection: 'TLS handshake pinned to TLS 1.3.', impact: 'Not a vulnerability; TLS 1.3 offers faster handshakes and removes legacy cipher suites.', remediation: 'Enable TLS 1.3 on the web server or load balancer.' })));
            }
            if (main.cipher && /(RC4|3DES|DES-CBC|NULL|EXPORT|MD5)/i.test(main.cipher)) {
                findings.push((0, findings_1.makeFinding)(Object.assign(Object.assign({}, base), { key: 'weak-cipher', title: `Weak cipher suite negotiated (${main.cipher})`, severity: 'medium', confidence: 'high', verification: 'confirmed', description: `The default handshake negotiated ${main.cipher}.`, evidence: [{ label: 'Cipher', value: main.cipher }, { label: 'Protocol', value: main.protocol || '?' }], detection: 'Default TLS handshake.', impact: 'Weak ciphers can be broken or downgraded.', remediation: 'Allow only AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).' })));
            }
            return (0, context_1.result)(findings, `${main.protocol} · ${main.cipher} · ${main.authorized ? 'trusted chain' : main.authorizationError}`);
        });
    },
};
