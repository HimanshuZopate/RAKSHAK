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
exports.wafMiddleware = exports.setWafConfig = exports.getWafConfig = void 0;
const geoip_lite_1 = __importDefault(require("geoip-lite"));
const trafficLog_model_1 = __importDefault(require("../model/trafficLog.model"));
const wafConfig_model_1 = __importDefault(require("../model/wafConfig.model"));
const serviceSocket_1 = require("../socket/serviceSocket");
let activeConfig = {
    mode: 'active',
    sqlInjection: true,
    xss: true,
    pathTraversal: true,
    commandInjection: true,
};
// Initialize config from MongoDB on startup
(() => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const configDoc = yield wafConfig_model_1.default.findOne();
        if (configDoc) {
            activeConfig = {
                mode: configDoc.mode,
                sqlInjection: configDoc.sqlInjection,
                xss: configDoc.xss,
                pathTraversal: configDoc.pathTraversal,
                commandInjection: configDoc.commandInjection,
            };
        }
        else {
            yield wafConfig_model_1.default.create(activeConfig);
        }
    }
    catch (err) {
        console.warn('[WAF] Could not initialize WafConfig from DB, using default active mode.');
    }
}))();
const getWafConfig = () => (Object.assign({}, activeConfig));
exports.getWafConfig = getWafConfig;
const setWafConfig = (newConfig) => __awaiter(void 0, void 0, void 0, function* () {
    activeConfig = Object.assign(Object.assign({}, activeConfig), newConfig);
    try {
        yield wafConfig_model_1.default.findOneAndUpdate({}, activeConfig, { upsert: true, new: true });
    }
    catch (err) {
        console.error('[WAF] Error saving WafConfig to DB:', err);
    }
    return Object.assign({}, activeConfig);
});
exports.setWafConfig = setWafConfig;
const SECURITY_RULES = [
    // 1. SQL Injection (SQLi)
    {
        category: 'SQLi',
        name: 'Tautology Condition (\' OR 1=1)',
        pattern: /(?:'|"|`)\s*(?:or|and)\s*[\w\d'"\(\)]+\s*=\s*[\w\d'"\(\)]+/i,
        enabledKey: 'sqlInjection',
    },
    {
        category: 'SQLi',
        name: 'Boolean Operator Bypass (\' OR TRUE)',
        pattern: /(?:'|"|`)\s*(?:or|and)\s+(?:true|false|null)\b/i,
        enabledKey: 'sqlInjection',
    },
    {
        category: 'SQLi',
        name: 'UNION SELECT Exfiltration',
        pattern: /\bunion\s+(?:all\s+)?select\b/i,
        enabledKey: 'sqlInjection',
    },
    {
        category: 'SQLi',
        name: 'SQL Data Manipulation / Schema Probe',
        pattern: /\b(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|alter\s+table|truncate\s+table|information_schema)\b/i,
        enabledKey: 'sqlInjection',
    },
    {
        category: 'SQLi',
        name: 'Time-Based Blind Injection (SLEEP / BENCHMARK)',
        pattern: /\b(?:sleep|benchmark|waitfor\s+delay)\s*\(/i,
        enabledKey: 'sqlInjection',
    },
    {
        category: 'SQLi',
        name: 'SQL Comment Truncation (--, /*)',
        pattern: /(?:--\s*|\/\*.*?\*\/|#\s*)/m,
        enabledKey: 'sqlInjection',
    },
    // 2. Cross-Site Scripting (XSS)
    {
        category: 'XSS',
        name: 'Script Tag Injection (<script>)',
        pattern: /<\s*\/?\s*script\b[^>]*>/i,
        enabledKey: 'xss',
    },
    {
        category: 'XSS',
        name: 'URI Scheme Execution (javascript: / data:text/html)',
        pattern: /(?:javascript|vbscript)\s*:\s*|data\s*:\s*text\/html/i,
        enabledKey: 'xss',
    },
    {
        category: 'XSS',
        name: 'Inline Event Handler (onload=, onerror=, etc.)',
        pattern: /\bon(?:error|load|click|mouseover|focus|blur|change|submit|input)\s*=\s*["'`]?[^"'`>]*\(?/i,
        enabledKey: 'xss',
    },
    {
        category: 'XSS',
        name: 'Malicious DOM Accessor (document.cookie)',
        pattern: /document\s*\.\s*(?:cookie|location|domain|write)/i,
        enabledKey: 'xss',
    },
    {
        category: 'XSS',
        name: 'HTML Element with Executable Attribute',
        pattern: /<\s*(?:iframe|object|embed|applet|svg|img|body|link|style|meta)\b[^>]*(?:src|href|data)\s*=\s*["']?(?:javascript:|data:text\/html)/i,
        enabledKey: 'xss',
    },
    // 3. Path Traversal & Local File Inclusion (LFI)
    {
        category: 'Path Traversal',
        name: 'Directory Traversal Relative Path (../)',
        pattern: /(?:\.{2,}[\/\\])+/i,
        enabledKey: 'pathTraversal',
    },
    {
        category: 'Path Traversal',
        name: 'URL-Encoded Directory Traversal (%2e%2e%2f)',
        pattern: /(?:%2e%2e(?:%2f|%5c|\/|\\))+/i,
        enabledKey: 'pathTraversal',
    },
    {
        category: 'Path Traversal',
        name: 'Sensitive System File Probe (/etc/passwd, win.ini)',
        pattern: /(?:etc[\/\\]passwd|etc[\/\\]shadow|boot\.ini|win\.ini|windows[\/\\]system32)/i,
        enabledKey: 'pathTraversal',
    },
    {
        category: 'Path Traversal',
        name: 'PHP/File Wrapper Injection',
        pattern: /\b(?:php|file|zip|phar|glob|data):\/\//i,
        enabledKey: 'pathTraversal',
    },
    // 4. Command Injection & Remote Code Execution (RCE)
    {
        category: 'Command Injection',
        name: 'Shell Chaining Operator (; cat, | bash, && whoami)',
        pattern: /(?:;|\||`|\$\()\s*(?:cat|ls|whoami|id|bash|sh|cmd|powershell|curl|wget|nc|ping)\b/i,
        enabledKey: 'commandInjection',
    },
    {
        category: 'Command Injection',
        name: 'JNDI / Log4Shell Remote Exploit',
        pattern: /\$\{jndi:(?:ldap|rmi|dns|nis):/i,
        enabledKey: 'commandInjection',
    },
];
/** Routes (relative to the /api mount) whose JSON body is free-form text sent only to the AI assistant. */
const FREE_TEXT_AI_ROUTES = new Set(['/ai/chat', '/ai/explain']);
/**
 * Recursively extracts and concatenates all string values from an object or array.
 */
function extractStrings(target, depth = 0) {
    if (depth > 6 || !target)
        return [];
    const results = [];
    if (typeof target === 'string') {
        results.push(target);
    }
    else if (Array.isArray(target)) {
        for (const item of target) {
            results.push(...extractStrings(item, depth + 1));
        }
    }
    else if (typeof target === 'object') {
        for (const key of Object.keys(target)) {
            results.push(key);
            results.push(...extractStrings(target[key], depth + 1));
        }
    }
    return results;
}
/**
 * Inspects a list of candidate strings against the active security rules.
 */
function inspectPayload(candidates, config) {
    for (const str of candidates) {
        if (!str || typeof str !== 'string' || str.length < 2)
            continue;
        // Decode URL encodings to catch evasion attempts like %27%20OR%201=1
        let decoded = str;
        try {
            decoded = decodeURIComponent(str);
        }
        catch (_a) {
            // Keep original if malformed URI component
        }
        for (const rule of SECURITY_RULES) {
            if (!config[rule.enabledKey])
                continue;
            if (rule.pattern.test(str) || (decoded !== str && rule.pattern.test(decoded))) {
                return {
                    threatType: rule.category,
                    ruleMatched: rule.name,
                    matchedPayload: str.length > 200 ? str.substring(0, 197) + '...' : str,
                };
            }
        }
    }
    return {
        threatType: 'None',
        ruleMatched: '',
        matchedPayload: '',
    };
}
/**
 * Resolves IP Geolocation (Country & City).
 */
function resolveGeoLocation(ip) {
    // Normalize loopback and private IPv4/IPv6 ranges
    const cleanIp = ip.replace(/^::ffff:/, '');
    const isPrivate = cleanIp === '127.0.0.1' ||
        cleanIp === '::1' ||
        cleanIp.startsWith('10.') ||
        cleanIp.startsWith('192.168.') ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIp) ||
        cleanIp === 'localhost';
    if (isPrivate) {
        return {
            country: 'Local Network',
            countryCode: 'LAN',
            city: 'Private Intranet',
        };
    }
    const geo = geoip_lite_1.default.lookup(cleanIp);
    if (geo) {
        return {
            country: geo.country || 'Unknown',
            countryCode: geo.country || 'XX',
            city: geo.city || 'Unknown City',
        };
    }
    return {
        country: 'Global Cloud',
        countryCode: 'GLOBAL',
        city: 'Unresolved IP',
    };
}
/**
 * WAF Middleware: Inspects incoming HTTP requests, classifies threats,
 * logs traffic to MongoDB, emits real-time WebSocket events, and enforces blocks.
 */
const wafMiddleware = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    // Exclude static assets or internal heartbeat routes from excessive logging
    if (req.path.startsWith('/favicon.ico') || req.path.startsWith('/socket.io/')) {
        return next();
    }
    // 1. Extract IP Address
    const rawIp = ((_b = (_a = req.headers['x-forwarded-for']) === null || _a === void 0 ? void 0 : _a.split(',')[0]) === null || _b === void 0 ? void 0 : _b.trim()) ||
        req.headers['x-real-ip'] ||
        req.headers['x-simulated-ip'] ||
        req.socket.remoteAddress ||
        '127.0.0.1';
    // 2. Gather all input vectors
    // Conversational AI endpoints carry free-form natural language (Markdown headings "#",
    // rules "---", and questions *about* SQLi/XSS payloads). Their bodies are forwarded only to
    // an LLM — never to a database query, shell or HTML sink — so body signatures are skipped
    // for these exact routes. URL, query string and headers are still inspected.
    const isFreeTextAIRoute = req.method === 'POST' && FREE_TEXT_AI_ROUTES.has(req.path.replace(/\/+$/, '').toLowerCase());
    const urlPayloads = [req.originalUrl || req.url, req.path];
    const queryPayloads = extractStrings(req.query);
    const bodyPayloads = isFreeTextAIRoute ? [] : extractStrings(req.body);
    const headerPayloads = extractStrings({
        'user-agent': req.headers['user-agent'],
        referer: req.headers['referer'],
        'x-payload-test': req.headers['x-payload-test'],
    });
    const allCandidates = [...urlPayloads, ...queryPayloads, ...bodyPayloads, ...headerPayloads];
    // 3. Inspect against rule engine
    const inspection = inspectPayload(allCandidates, activeConfig);
    const isThreat = inspection.threatType !== 'None';
    // 4. Determine Action based on active config mode
    const action = isThreat && activeConfig.mode === 'active' ? 'Blocked' : 'Allowed';
    const statusCode = action === 'Blocked' ? 403 : 200;
    // 5. Geolocation Lookup
    const simulatedCountry = req.headers['x-mock-country'];
    let geo = resolveGeoLocation(rawIp);
    if (simulatedCountry) {
        geo = {
            country: simulatedCountry,
            countryCode: simulatedCountry.substring(0, 2).toUpperCase(),
            city: req.headers['x-mock-city'] || 'Simulated City',
        };
    }
    // 6. Build Traffic Log record
    const logData = {
        ipAddress: rawIp.replace(/^::ffff:/, ''),
        method: req.method,
        endpoint: req.originalUrl || req.url,
        payload: inspection.matchedPayload ||
            (isFreeTextAIRoute
                ? '[conversation content not logged]'
                : req.method === 'POST'
                    ? JSON.stringify(req.body || '').substring(0, 150)
                    : ''),
        threatType: inspection.threatType,
        action,
        statusCode,
        country: geo.country,
        countryCode: geo.countryCode,
        city: geo.city,
        userAgent: (req.headers['user-agent'] || '').substring(0, 120),
        ruleMatched: inspection.ruleMatched,
        timestamp: new Date(),
    };
    // 7. Asynchronous logging & WebSocket broadcasting (Non-blocking)
    setImmediate(() => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const savedDoc = yield trafficLog_model_1.default.create(logData);
            (0, serviceSocket_1.emitLiveTrafficUpdate)(savedDoc.toObject());
        }
        catch (logErr) {
            console.error('[WAF LOG ERROR] Could not save traffic record to MongoDB:', logErr);
            // Still broadcast to connected sockets so UI feels responsive
            (0, serviceSocket_1.emitLiveTrafficUpdate)(logData);
        }
    }));
    // 8. If Blocked, terminate request immediately with 403 Forbidden
    if (action === 'Blocked') {
        return res.status(403).json({
            error: 'Forbidden by Web Application Firewall (WAF)',
            threatType: inspection.threatType,
            ruleMatched: inspection.ruleMatched,
            action: 'Blocked',
            incidentTimestamp: logData.timestamp.toISOString(),
            clientIp: logData.ipAddress,
            message: 'Malicious payload pattern detected and neutralized by WAF intrusion defense.',
        });
    }
    // Request is Allowed (either clean or simulation mode enabled)
    next();
});
exports.wafMiddleware = wafMiddleware;
exports.default = exports.wafMiddleware;
