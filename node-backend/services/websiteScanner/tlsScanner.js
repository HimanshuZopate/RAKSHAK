"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.inspectTlsCertificate = void 0;
const tls_1 = __importDefault(require("tls"));
/**
 * Check if a hostname matches a Subject Alternative Name (SAN) pattern
 * Handles standard wildcards e.g. *.example.com matches sub.example.com
 */
const matchesDomainPattern = (hostname, pattern) => {
    const h = hostname.toLowerCase();
    const p = pattern.toLowerCase().trim();
    if (p.startsWith('dns:')) {
        return matchesDomainPattern(h, p.substring(4));
    }
    if (h === p)
        return true;
    if (p.startsWith('*.')) {
        const baseDomain = p.substring(2);
        // Single-level wildcard match
        if (h.endsWith(baseDomain) && h.split('.').length === p.split('.').length) {
            return true;
        }
    }
    return false;
};
/**
 * Perform a real TLS handshake and peer certificate extraction
 */
const inspectTlsCertificate = (target, timeoutMs = 6000) => {
    return new Promise((resolve) => {
        const port = target.port === 80 ? 443 : target.port;
        const socketOptions = {
            host: target.primaryIp,
            port,
            servername: target.hostname,
            rejectUnauthorized: false,
            timeout: timeoutMs,
        };
        let socket;
        try {
            socket = tls_1.default.connect(socketOptions, () => {
                var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
                try {
                    const peerCert = socket.getPeerCertificate(true);
                    const authorized = socket.authorized;
                    const authorizationError = socket.authorizationError
                        ? String(socket.authorizationError)
                        : null;
                    const protocol = socket.getProtocol();
                    const cipherInfo = socket.getCipher();
                    const cipher = cipherInfo ? `${cipherInfo.name} (${cipherInfo.version})` : null;
                    socket.destroy();
                    if (!peerCert || Object.keys(peerCert).length === 0) {
                        return resolve({
                            available: false,
                            status: 'Unable to Verify',
                            issuer: { raw: 'Unknown' },
                            subject: { raw: 'Unknown' },
                            subjectAltNames: [],
                            validFrom: null,
                            validTo: null,
                            daysRemaining: null,
                            isExpired: false,
                            isExpiringSoon: false,
                            hostnameMatched: false,
                            chainTrusted: false,
                            detailsMessage: 'No peer certificate returned by the remote server.',
                        });
                    }
                    const validFromDate = peerCert.valid_from ? new Date(peerCert.valid_from) : null;
                    const validToDate = peerCert.valid_to ? new Date(peerCert.valid_to) : null;
                    let daysRemaining = null;
                    let isExpired = false;
                    let isExpiringSoon = false;
                    if (validToDate && !isNaN(validToDate.getTime())) {
                        const diffMs = validToDate.getTime() - Date.now();
                        daysRemaining = Math.floor(diffMs / (1000 * 60 * 60 * 24));
                        isExpired = daysRemaining < 0;
                        isExpiringSoon = daysRemaining >= 0 && daysRemaining <= 30; // 30-day threshold
                    }
                    // Parse SANs
                    const rawSan = peerCert.subjectaltname || '';
                    const sans = rawSan
                        .split(',')
                        .map((s) => s.trim().replace(/^DNS:/i, ''))
                        .filter(Boolean);
                    // Hostname verification
                    const subjectCN = ((_a = peerCert.subject) === null || _a === void 0 ? void 0 : _a.CN) || '';
                    const candidateNames = [...sans];
                    if (subjectCN && !candidateNames.includes(subjectCN)) {
                        candidateNames.push(subjectCN);
                    }
                    const hostnameMatched = candidateNames.some((pattern) => matchesDomainPattern(target.hostname, pattern));
                    // Determine status
                    let status = 'Validity Dates OK';
                    let detailsMessage = `Certificate is valid and active for ${daysRemaining} more days.`;
                    if (isExpired) {
                        status = 'Expired';
                        detailsMessage = `Certificate expired on ${validToDate === null || validToDate === void 0 ? void 0 : validToDate.toUTCString()}.`;
                    }
                    else if (isExpiringSoon) {
                        status = 'Expiring Soon';
                        detailsMessage = `Certificate expires within 30 days (${daysRemaining} days remaining). Renewal recommended.`;
                    }
                    else if (!hostnameMatched) {
                        status = 'Certificate Validation Failed';
                        detailsMessage = `Hostname mismatch: certificate is issued for ${candidateNames.slice(0, 3).join(', ')} but target is ${target.hostname}.`;
                    }
                    else if (!authorized && authorizationError) {
                        status = 'Certificate Validation Failed';
                        detailsMessage = `Certificate trust issue: ${authorizationError}.`;
                    }
                    return resolve({
                        available: true,
                        status,
                        issuer: {
                            commonName: (_b = peerCert.issuer) === null || _b === void 0 ? void 0 : _b.CN,
                            organization: (_c = peerCert.issuer) === null || _c === void 0 ? void 0 : _c.O,
                            country: (_d = peerCert.issuer) === null || _d === void 0 ? void 0 : _d.C,
                            raw: ((_e = peerCert.issuer) === null || _e === void 0 ? void 0 : _e.O) || ((_f = peerCert.issuer) === null || _f === void 0 ? void 0 : _f.CN) || 'Unknown Issuer',
                        },
                        subject: {
                            commonName: (_g = peerCert.subject) === null || _g === void 0 ? void 0 : _g.CN,
                            organization: (_h = peerCert.subject) === null || _h === void 0 ? void 0 : _h.O,
                            raw: ((_j = peerCert.subject) === null || _j === void 0 ? void 0 : _j.CN) || ((_k = peerCert.subject) === null || _k === void 0 ? void 0 : _k.O) || target.hostname,
                        },
                        subjectAltNames: sans,
                        validFrom: validFromDate ? validFromDate.toUTCString() : null,
                        validTo: validToDate ? validToDate.toUTCString() : null,
                        daysRemaining,
                        isExpired,
                        isExpiringSoon,
                        hostnameMatched,
                        chainTrusted: authorized,
                        validationError: authorizationError,
                        protocol,
                        cipher,
                        fingerprint: peerCert.fingerprint256 || peerCert.fingerprint,
                        serialNumber: peerCert.serialNumber,
                        detailsMessage,
                    });
                }
                catch (err) {
                    socket.destroy();
                    return resolve({
                        available: false,
                        status: 'Unable to Verify',
                        issuer: { raw: 'Error' },
                        subject: { raw: 'Error' },
                        subjectAltNames: [],
                        validFrom: null,
                        validTo: null,
                        daysRemaining: null,
                        isExpired: false,
                        isExpiringSoon: false,
                        hostnameMatched: false,
                        chainTrusted: false,
                        detailsMessage: `Failed to parse TLS certificate: ${err.message || 'Inspection error'}.`,
                    });
                }
            });
            socket.on('timeout', () => {
                socket.destroy();
                resolve({
                    available: false,
                    status: 'Unable to Verify',
                    issuer: { raw: 'Timeout' },
                    subject: { raw: 'Timeout' },
                    subjectAltNames: [],
                    validFrom: null,
                    validTo: null,
                    daysRemaining: null,
                    isExpired: false,
                    isExpiringSoon: false,
                    hostnameMatched: false,
                    chainTrusted: false,
                    detailsMessage: 'TLS handshake timed out after 6 seconds.',
                });
            });
            socket.on('error', (err) => {
                socket.destroy();
                resolve({
                    available: false,
                    status: 'Unable to Verify',
                    issuer: { raw: 'Connection Error' },
                    subject: { raw: 'Connection Error' },
                    subjectAltNames: [],
                    validFrom: null,
                    validTo: null,
                    daysRemaining: null,
                    isExpired: false,
                    isExpiringSoon: false,
                    hostnameMatched: false,
                    chainTrusted: false,
                    detailsMessage: `TLS connection failed: ${err.code || err.message || 'Cannot establish secure socket'}.`,
                });
            });
        }
        catch (err) {
            resolve({
                available: false,
                status: 'Unable to Verify',
                issuer: { raw: 'Error' },
                subject: { raw: 'Error' },
                subjectAltNames: [],
                validFrom: null,
                validTo: null,
                daysRemaining: null,
                isExpired: false,
                isExpiringSoon: false,
                hostnameMatched: false,
                chainTrusted: false,
                detailsMessage: `TLS initialization failed: ${err.message || 'Internal socket error'}.`,
            });
        }
    });
};
exports.inspectTlsCertificate = inspectTlsCertificate;
