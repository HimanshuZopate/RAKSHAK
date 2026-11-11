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
exports.validateTargetUrl = exports.isPrivateOrReservedIP = exports.isPrivateOrReservedIPv6 = exports.isPrivateOrReservedIPv4 = void 0;
const dns_1 = __importDefault(require("dns"));
const net_1 = __importDefault(require("net"));
const url_1 = require("url");
/**
 * Check if an IPv4 address falls within private, loopback, or reserved ranges
 */
const isPrivateOrReservedIPv4 = (ip) => {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN))
        return true;
    const [b0, b1, b2, b3] = parts;
    // 0.0.0.0/8 (Current network)
    if (b0 === 0)
        return true;
    // 10.0.0.0/8 (Private Class A RFC1918)
    if (b0 === 10)
        return true;
    // 127.0.0.0/8 (Loopback)
    if (b0 === 127)
        return true;
    // 100.64.0.0/10 (Shared Address Space / Carrier Grade NAT RFC6598)
    if (b0 === 100 && b1 >= 64 && b1 <= 127)
        return true;
    // 169.254.0.0/16 (Link-Local RFC3927 & Cloud Instance Metadata e.g. 169.254.169.254)
    if (b0 === 169 && b1 === 254)
        return true;
    // 172.16.0.0/12 (Private Class B RFC1918: 172.16.0.0 - 172.31.255.255)
    if (b0 === 172 && b1 >= 16 && b1 <= 31)
        return true;
    // 192.0.0.0/24 (IETF Protocol Assignments RFC6890)
    if (b0 === 192 && b1 === 0 && b2 === 0)
        return true;
    // 192.0.2.0/24 (TEST-NET-1 RFC5737)
    if (b0 === 192 && b1 === 0 && b2 === 2)
        return true;
    // 192.168.0.0/16 (Private Class C RFC1918)
    if (b0 === 192 && b1 === 168)
        return true;
    // 198.18.0.0/15 (Network Interconnect Benchmark Testing RFC2544)
    if (b0 === 198 && (b1 === 18 || b1 === 19))
        return true;
    // 198.51.100.0/24 (TEST-NET-2 RFC5737)
    if (b0 === 198 && b1 === 51 && b2 === 100)
        return true;
    // 203.0.113.0/24 (TEST-NET-3 RFC5737)
    if (b0 === 203 && b1 === 0 && b2 === 113)
        return true;
    // 224.0.0.0/4 (Multicast RFC5771: 224.0.0.0 - 239.255.255.255)
    if (b0 >= 224 && b0 <= 239)
        return true;
    // 240.0.0.0/4 (Reserved RFC1112)
    if (b0 >= 240)
        return true;
    // 255.255.255.255/32 (Broadcast)
    if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255)
        return true;
    return false;
};
exports.isPrivateOrReservedIPv4 = isPrivateOrReservedIPv4;
/**
 * Check if an IPv6 address falls within private, loopback, or reserved ranges
 */
const isPrivateOrReservedIPv6 = (ip) => {
    const normalized = ip.toLowerCase();
    // Loopback (::1) and Unspecified (::)
    if (normalized === '::1' || normalized === '::')
        return true;
    // IPv4-mapped IPv6 (e.g., ::ffff:192.168.1.1 or ::ffff:c0a8:0101)
    if (normalized.startsWith('::ffff:')) {
        const ipv4Part = normalized.substring(7);
        if (net_1.default.isIPv4(ipv4Part)) {
            return (0, exports.isPrivateOrReservedIPv4)(ipv4Part);
        }
        return true;
    }
    // Unique Local Addresses (fc00::/7 -> fc00... to fdff...)
    if (normalized.startsWith('fc') || normalized.startsWith('fd'))
        return true;
    // Link-Local Unicast (fe80::/10 -> fe8... to feb...)
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
        return true;
    }
    // Documentation Prefix (2001:db8::/32)
    if (normalized.startsWith('2001:db8:'))
        return true;
    // Multicast (ff00::/8)
    if (normalized.startsWith('ff'))
        return true;
    return false;
};
exports.isPrivateOrReservedIPv6 = isPrivateOrReservedIPv6;
/**
 * Unified IP address validator
 */
const isPrivateOrReservedIP = (ip) => {
    if (net_1.default.isIPv4(ip))
        return (0, exports.isPrivateOrReservedIPv4)(ip);
    if (net_1.default.isIPv6(ip))
        return (0, exports.isPrivateOrReservedIPv6)(ip);
    return true; // Unknown/malformed IP format treated as unsafe
};
exports.isPrivateOrReservedIP = isPrivateOrReservedIP;
/**
 * Comprehensive SSRF Validator for incoming target URLs
 */
const validateTargetUrl = (inputUrl) => __awaiter(void 0, void 0, void 0, function* () {
    if (!inputUrl || typeof inputUrl !== 'string') {
        throw new Error('Website URL parameter is required.');
    }
    const trimmed = inputUrl.trim();
    if (trimmed.length > 2048) {
        throw new Error('URL exceeds the maximum permitted length (2048 characters).');
    }
    // Prepend https:// if protocol is omitted
    let candidate = trimmed;
    if (!/^https?:\/\//i.test(candidate)) {
        candidate = `https://${candidate}`;
    }
    let parsed;
    try {
        parsed = new url_1.URL(candidate);
    }
    catch (_a) {
        throw new Error('Invalid URL format. Please enter a valid HTTP or HTTPS website URL.');
    }
    // 1. Strict protocol check
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`Unsupported URL protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.`);
    }
    // 2. Reject embedded authentication credentials
    if (parsed.username || parsed.password) {
        throw new Error('URLs with embedded credentials (username/password) are not permitted.');
    }
    // 3. Validate hostname
    const hostname = parsed.hostname.toLowerCase();
    if (!hostname || hostname.length === 0) {
        throw new Error('Target hostname could not be identified.');
    }
    // Disallow explicit localhost names
    if (hostname === 'localhost' ||
        hostname.endsWith('.localhost') ||
        hostname === '127.0.0.1' ||
        hostname === '::1' ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.local')) {
        throw new Error('Target host resolves to a local or restricted environment.');
    }
    // 4. If hostname is an IP literal, validate directly
    if (net_1.default.isIP(hostname)) {
        if ((0, exports.isPrivateOrReservedIP)(hostname)) {
            throw new Error('Target IP address belongs to a private, loopback, or reserved network range.');
        }
    }
    // 5. DNS Resolution & Rebinding Check
    // Resolve all IPv4 and IPv6 records
    let addresses = [];
    try {
        addresses = yield dns_1.default.promises.lookup(hostname, { all: true });
    }
    catch (err) {
        throw new Error(`DNS resolution failed for hostname "${hostname}": ${err.code || 'Domain not found'}.`);
    }
    if (!addresses || addresses.length === 0) {
        throw new Error(`No DNS records found for hostname "${hostname}".`);
    }
    const resolvedIps = addresses.map((a) => a.address);
    // Check every resolved address against private/reserved ranges
    for (const record of addresses) {
        if ((0, exports.isPrivateOrReservedIP)(record.address)) {
            throw new Error(`Hostname "${hostname}" resolves to a restricted or private address.`);
        }
    }
    // Select primary IP
    const primaryRecord = addresses.find((a) => a.family === 4) || addresses[0];
    const port = parsed.port
        ? parseInt(parsed.port, 10)
        : parsed.protocol === 'https:'
            ? 443
            : 80;
    // Disallow non-standard ports to prevent port scanning abuse
    if (port !== 80 && port !== 443 && port !== 8080 && port !== 8443) {
        throw new Error(`Port ${port} is restricted. Only standard web ports (80, 443, 8080, 8443) can be scanned.`);
    }
    return {
        originalUrl: inputUrl,
        normalizedUrl: parsed.toString(),
        protocol: parsed.protocol,
        hostname,
        port,
        pathname: parsed.pathname || '/',
        resolvedIps,
        primaryIp: primaryRecord.address,
        ipFamily: primaryRecord.family,
    };
});
exports.validateTargetUrl = validateTargetUrl;
