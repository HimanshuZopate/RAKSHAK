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
exports.inspectSecurityHeaders = void 0;
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const url_1 = require("url");
const ssrfProtection_1 = require("./ssrfProtection");
/**
 * Execute a safe HTTP/HTTPS request pinned to a validated target
 * Follows at most 3 redirects, validating each redirect target through SSRF rules
 */
const safeFetchHeaders = (target, isHttps, maxRedirects = 3) => __awaiter(void 0, void 0, void 0, function* () {
    let currentTarget = target;
    let currentIsHttps = isHttps;
    let redirectsCount = 0;
    let redirectedToHttps = false;
    while (redirectsCount <= maxRedirects) {
        const protocolModule = currentIsHttps ? https_1.default : http_1.default;
        const defaultPort = currentIsHttps ? 443 : 80;
        const port = currentTarget.port || defaultPort;
        const requestResult = yield new Promise((resolve, reject) => {
            const options = {
                hostname: currentTarget.hostname,
                port,
                path: currentTarget.pathname || '/',
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CybersecurityScanner/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'close',
                },
                timeout: 6000,
                // Pin DNS resolution to pre-validated IP to defeat DNS rebinding!
                lookup: (hostname, opts, cb) => {
                    cb(null, currentTarget.primaryIp, currentTarget.ipFamily);
                },
                rejectUnauthorized: false, // We check cert separately; we still want headers on self-signed certs
            };
            const req = protocolModule.request(options, (res) => {
                const headers = {};
                for (const [key, val] of Object.entries(res.headers)) {
                    if (Array.isArray(val)) {
                        headers[key.toLowerCase()] = val.join(', ');
                    }
                    else if (val) {
                        headers[key.toLowerCase()] = String(val);
                    }
                }
                const statusCode = res.statusCode || 0;
                const location = headers['location'];
                // Terminate body immediately - we only analyze headers
                res.destroy();
                resolve({ statusCode, headers, location });
            });
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Connection timed out after 6 seconds.'));
            });
            req.on('error', (err) => {
                req.destroy();
                reject(err);
            });
            req.end();
        });
        const isRedirect = [301, 302, 303, 307, 308].includes(requestResult.statusCode) &&
            requestResult.location;
        if (isRedirect && redirectsCount < maxRedirects) {
            redirectsCount++;
            const rawLocation = requestResult.location;
            let resolvedNextUrl;
            try {
                const base = `${currentIsHttps ? 'https' : 'http'}://${currentTarget.hostname}:${port}`;
                resolvedNextUrl = new url_1.URL(rawLocation, base).toString();
            }
            catch (_a) {
                // Unparseable location - stop redirect chain
                return {
                    statusCode: requestResult.statusCode,
                    headers: requestResult.headers,
                    finalUrl: currentTarget.normalizedUrl,
                    redirectsObserved: redirectsCount,
                    redirectedToHttps,
                };
            }
            if (resolvedNextUrl.startsWith('https://')) {
                redirectedToHttps = true;
            }
            // Re-validate the redirect target against all SSRF policies!
            const nextValidated = yield (0, ssrfProtection_1.validateTargetUrl)(resolvedNextUrl);
            currentTarget = nextValidated;
            currentIsHttps = nextValidated.protocol === 'https:';
        }
        else {
            // Completed terminal request
            return {
                statusCode: requestResult.statusCode,
                headers: requestResult.headers,
                finalUrl: currentTarget.normalizedUrl,
                redirectsObserved: redirectsCount,
                redirectedToHttps,
            };
        }
    }
    throw new Error('Maximum redirect limit (3) exceeded.');
});
/**
 * Check whether port 80 redirects to HTTPS
 */
const checkHttpToHttpsRedirection = (target) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const res = yield new Promise((resolve, reject) => {
            const options = {
                hostname: target.hostname,
                port: 80,
                path: target.pathname || '/',
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CybersecurityScanner/1.0',
                    'Connection': 'close',
                },
                timeout: 4000,
                lookup: (hostname, opts, cb) => {
                    cb(null, target.primaryIp, target.ipFamily);
                },
            };
            const req = http_1.default.request(options, (res) => {
                const location = res.headers.location;
                res.destroy();
                resolve({ statusCode: res.statusCode || 0, location });
            });
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Timeout'));
            });
            req.on('error', (err) => {
                req.destroy();
                reject(err);
            });
            req.end();
        });
        if ([301, 302, 307, 308].includes(res.statusCode) && res.location) {
            return res.location.toLowerCase().startsWith('https://');
        }
        return false;
    }
    catch (_b) {
        return false;
    }
});
/**
 * Perform comprehensive HTTP Security Header analysis
 */
const inspectSecurityHeaders = (target) => __awaiter(void 0, void 0, void 0, function* () {
    let httpsResponse = null;
    let httpsAvailable = false;
    let httpsStatus = 'Unable to Verify';
    let detailsMessage = '';
    try {
        // Probe HTTPS endpoint directly
        httpsResponse = yield safeFetchHeaders(target, true, 3);
        httpsAvailable = httpsResponse.statusCode > 0;
        httpsStatus = httpsAvailable ? 'HTTPS Available' : 'HTTPS Unavailable';
        detailsMessage = `HTTPS reachable with HTTP status ${httpsResponse.statusCode}.`;
    }
    catch (err) {
        httpsAvailable = false;
        httpsStatus = 'HTTPS Unavailable';
        detailsMessage = `HTTPS connection failed: ${err.message || 'Unable to establish secure HTTP connection'}.`;
    }
    // Check HTTP-to-HTTPS redirect on port 80
    const httpToHttpsRedirect = yield checkHttpToHttpsRedirection(target);
    const headers = (httpsResponse === null || httpsResponse === void 0 ? void 0 : httpsResponse.headers) || {};
    const headerFindings = [];
    // 1. Strict-Transport-Security (HSTS)
    const hsts = headers['strict-transport-security'];
    if (hsts) {
        const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        const hasSubDomains = /includesubdomains/i.test(hsts);
        const hasPreload = /preload/i.test(hsts);
        if (maxAge >= 31536000) {
            headerFindings.push({
                header: 'Strict-Transport-Security (HSTS)',
                value: hsts,
                status: 'Present',
                importance: 'High',
                explanation: 'Enforces HTTPS for at least 1 year (31,536,000 seconds), preventing downgrade and SSL stripping attacks.',
                recommendation: hasSubDomains ? 'Optimal HSTS policy observed.' : 'Consider adding includeSubDomains if all subdomains support HTTPS.',
            });
        }
        else if (maxAge > 0) {
            headerFindings.push({
                header: 'Strict-Transport-Security (HSTS)',
                value: hsts,
                status: 'Needs Review',
                importance: 'High',
                explanation: `HSTS is active but has a short max-age duration (${maxAge}s). Standard best practice recommends at least 1 year (31536000s).`,
                recommendation: 'Increase max-age to 31536000 (1 year) once you are confident HTTPS is working across your domain.',
            });
        }
        else {
            headerFindings.push({
                header: 'Strict-Transport-Security (HSTS)',
                value: hsts,
                status: 'Needs Review',
                importance: 'High',
                explanation: 'HSTS header has an invalid or zero max-age directive, offering no transport protection.',
                recommendation: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains.',
            });
        }
    }
    else {
        headerFindings.push({
            header: 'Strict-Transport-Security (HSTS)',
            value: null,
            status: 'Missing',
            importance: 'High',
            explanation: 'Missing HSTS leaves users vulnerable to Man-in-the-Middle (MITM) downgrade attacks and SSL stripping on initial visits.',
            recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to all HTTPS responses.',
        });
    }
    // 2. Content-Security-Policy (CSP)
    const csp = headers['content-security-policy'];
    if (csp) {
        const hasUnsafeInline = /'unsafe-inline'/i.test(csp);
        const hasUnsafeEval = /'unsafe-eval'/i.test(csp);
        const hasFrameAncestors = /frame-ancestors/i.test(csp);
        if (hasUnsafeInline || hasUnsafeEval) {
            headerFindings.push({
                header: 'Content-Security-Policy (CSP)',
                value: csp.length > 120 ? `${csp.substring(0, 120)}...` : csp,
                status: 'Needs Review',
                importance: 'High',
                explanation: `CSP is present but includes permissive directives (${[hasUnsafeInline && "'unsafe-inline'", hasUnsafeEval && "'unsafe-eval'"].filter(Boolean).join(', ')}), which weaken Cross-Site Scripting (XSS) defenses.`,
                recommendation: 'Migrate inline scripts to cryptographic nonces or hashes (e.g., \'nonce-...\') and eliminate unsafe-eval.',
            });
        }
        else {
            headerFindings.push({
                header: 'Content-Security-Policy (CSP)',
                value: csp.length > 120 ? `${csp.substring(0, 120)}...` : csp,
                status: 'Present',
                importance: 'High',
                explanation: 'Active Content Security Policy restricts authorized sources of scripts, styles, and external resources.',
                recommendation: hasFrameAncestors ? 'Well-configured CSP policy observed.' : 'Consider adding frame-ancestors to prevent clickjacking.',
            });
        }
    }
    else {
        headerFindings.push({
            header: 'Content-Security-Policy (CSP)',
            value: null,
            status: 'Missing',
            importance: 'High',
            explanation: 'Without a Content Security Policy, modern browsers cannot restrict unauthorized script execution or data exfiltration during XSS attacks.',
            recommendation: 'Define a Content-Security-Policy starting with a strict "default-src \'self\'" baseline.',
        });
    }
    // 3. X-Content-Type-Options
    const xcto = headers['x-content-type-options'];
    if (xcto && xcto.toLowerCase().includes('nosniff')) {
        headerFindings.push({
            header: 'X-Content-Type-Options',
            value: xcto,
            status: 'Present',
            importance: 'Medium',
            explanation: 'Configured with "nosniff", preventing MIME-type confusion attacks and executable content sniffing.',
            recommendation: 'Configuration is compliant with security standards.',
        });
    }
    else {
        headerFindings.push({
            header: 'X-Content-Type-Options',
            value: xcto || null,
            status: xcto ? 'Needs Review' : 'Missing',
            importance: 'Medium',
            explanation: 'Missing or misconfigured "nosniff" allows older browsers to override declared Content-Type headers, enabling MIME-sniffing exploits.',
            recommendation: 'Add "X-Content-Type-Options: nosniff" to all HTTP responses.',
        });
    }
    // 4. X-Frame-Options (considering CSP frame-ancestors)
    const xfo = headers['x-frame-options'];
    const cspHasFrameAncestors = csp ? /frame-ancestors/i.test(csp) : false;
    if (xfo) {
        const val = xfo.toUpperCase();
        if (val === 'DENY' || val === 'SAMEORIGIN') {
            headerFindings.push({
                header: 'X-Frame-Options',
                value: xfo,
                status: 'Present',
                importance: 'Medium',
                explanation: `Configured with "${val}", protecting your pages from clickjacking and unauthorized iframe embedding.`,
                recommendation: 'Configuration is compliant. Note: CSP frame-ancestors is the modern replacement standard.',
            });
        }
        else {
            headerFindings.push({
                header: 'X-Frame-Options',
                value: xfo,
                status: 'Needs Review',
                importance: 'Medium',
                explanation: `Header value "${xfo}" may not be supported across all modern user agents.`,
                recommendation: 'Use "DENY" or "SAMEORIGIN", or enforce framing policies via CSP frame-ancestors.',
            });
        }
    }
    else if (cspHasFrameAncestors) {
        headerFindings.push({
            header: 'X-Frame-Options (CSP Alternative)',
            value: 'Protected via CSP frame-ancestors',
            status: 'Present',
            importance: 'Medium',
            explanation: 'While X-Frame-Options is omitted, Content-Security-Policy frame-ancestors provides superior modern framing and clickjacking protection.',
            recommendation: 'Optional: Add X-Frame-Options: SAMEORIGIN for legacy browser fallback.',
        });
    }
    else {
        headerFindings.push({
            header: 'X-Frame-Options',
            value: null,
            status: 'Missing',
            importance: 'Medium',
            explanation: 'Missing anti-framing headers leave your web pages vulnerable to clickjacking attacks inside malicious iframes.',
            recommendation: 'Add "X-Frame-Options: SAMEORIGIN" or define "frame-ancestors \'self\'" in CSP.',
        });
    }
    // 5. Referrer-Policy
    const rp = headers['referrer-policy'];
    if (rp) {
        const isPermissive = /unsafe-url|no-referrer-when-downgrade/i.test(rp);
        headerFindings.push({
            header: 'Referrer-Policy',
            value: rp,
            status: isPermissive ? 'Needs Review' : 'Present',
            importance: 'Low',
            explanation: isPermissive
                ? 'Referrer policy is configured but uses a permissive directive that may leak sensitive path or query parameters to third parties.'
                : 'Restricts sensitive path and query parameters transmitted in the HTTP Referer header when navigating external sites.',
            recommendation: isPermissive
                ? 'Set Referrer-Policy: strict-origin-when-cross-origin for balanced privacy and usability.'
                : 'Configuration is compliant with modern privacy standards.',
        });
    }
    else {
        headerFindings.push({
            header: 'Referrer-Policy',
            value: null,
            status: 'Missing',
            importance: 'Low',
            explanation: 'Missing Referrer-Policy defaults to browser behavior, which might expose internal URLs and query parameters to external links.',
            recommendation: 'Set "Referrer-Policy: strict-origin-when-cross-origin".',
        });
    }
    // 6. Permissions-Policy
    const pp = headers['permissions-policy'] || headers['feature-policy'];
    if (pp) {
        headerFindings.push({
            header: 'Permissions-Policy',
            value: pp.length > 80 ? `${pp.substring(0, 80)}...` : pp,
            status: 'Present',
            importance: 'Informational',
            explanation: 'Restricts browser hardware APIs such as camera, microphone, geolocation, and payment systems.',
            recommendation: 'Permissions-Policy active. Ensure only necessary APIs are enabled.',
        });
    }
    else {
        headerFindings.push({
            header: 'Permissions-Policy',
            value: null,
            status: 'Missing',
            importance: 'Informational',
            explanation: 'Header is not configured. This is an informational finding; omitting it is common and does not imply a critical vulnerability.',
            recommendation: 'Consider adding Permissions-Policy: camera=(), microphone=(), geolocation=() to lock down unused browser APIs.',
        });
    }
    // Server info disclosure check
    const serverHeader = headers['server'];
    const poweredBy = headers['x-powered-by'];
    const leaksVersion = Boolean((serverHeader && /\d+\.\d+/.test(serverHeader)) ||
        (poweredBy && /\d+\.\d+/.test(poweredBy)));
    return {
        httpsAvailable,
        httpsStatus,
        httpsStatusCode: (httpsResponse === null || httpsResponse === void 0 ? void 0 : httpsResponse.statusCode) || null,
        finalUrl: (httpsResponse === null || httpsResponse === void 0 ? void 0 : httpsResponse.finalUrl) || target.normalizedUrl,
        httpToHttpsRedirect,
        redirectCount: (httpsResponse === null || httpsResponse === void 0 ? void 0 : httpsResponse.redirectsObserved) || 0,
        rawHeaders: headers,
        headerFindings,
        serverInfo: {
            serverHeader: serverHeader || null,
            poweredBy: poweredBy || null,
            leaksVersion,
        },
        detailsMessage,
    };
});
exports.inspectSecurityHeaders = inspectSecurityHeaders;
