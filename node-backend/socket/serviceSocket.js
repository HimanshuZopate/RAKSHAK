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
exports.setupSocketIO = exports.emitLiveTrafficUpdate = exports.getSocketIO = void 0;
const socket_io_1 = require("socket.io");
const jwt_util_1 = require("../util/jwt.util");
const service_model_1 = __importDefault(require("../model/service.model"));
const target_model_1 = require("../model/target.model");
const scanReport_model_1 = require("../model/scanReport.model");
const portScanner_1 = require("../scanners/portScanner");
const headerScanner_1 = require("../scanners/headerScanner");
const systemAuditor_1 = require("../scanners/systemAuditor");
const fileMonitor_1 = require("../scanners/fileMonitor");
const malwareScanner_1 = require("../scanners/malwareScanner");
const path_1 = __importDefault(require("path"));
const parseRawCookieHeader = (rawCookie) => {
    if (!rawCookie)
        return {};
    const result = {};
    rawCookie.split(';').forEach((item) => {
        const parts = item.trim().split('=');
        if (parts.length >= 2) {
            const key = parts[0];
            const val = parts.slice(1).join('=');
            result[key] = decodeURIComponent(val);
        }
    });
    return result;
};
/**
 * Generate rich, realistic security terminal logs tailored to each service
 */
const generateLogsForService = (serviceName) => {
    const baseSteps = [
        { level: 'INFO', message: `[SYSTEM] Initializing telemetry runtime for ${serviceName}...` },
        { level: 'INFO', message: '[AUTH] Validating analyst credentials and JWT session signatures...' },
        { level: 'INFO', message: '[NETWORK] Binding ephemeral socket to target sandbox container...' },
    ];
    let specificSteps = [];
    if (serviceName.toLowerCase().includes('vulnerability')) {
        specificSteps = [
            { level: 'INFO', message: '[SCAN] Loading NVD (National Vulnerability Database) feed v2026.10...' },
            { level: 'INFO', message: '[PROBE] Executing passive TCP SYN port sweep across ports 1-65535...' },
            { level: 'WARN', message: '[WARN] Open non-standard listener detected on port 9200 (Elasticsearch cluster)...' },
            { level: 'INFO', message: '[CURL] Simulating HTTP Header injection: testing Host, X-Forwarded-For...' },
            { level: 'ALERT', message: '[CVE-2024-3400] Scanning telemetry interface for arbitrary command execution...' },
            { level: 'WARN', message: '[FINDING] Subresource Integrity (SRI) missing on 2 external CDN scripts...' },
            { level: 'INFO', message: '[DEPS] Inspecting npm dependency tree for vulnerable transitive packages...' },
            { level: 'SUCCESS', message: '[PATCH] 0 critical RCE exploits found. 24 medium warnings cataloged.' },
        ];
    }
    else if (serviceName.toLowerCase().includes('access')) {
        specificSteps = [
            { level: 'INFO', message: '[IAM] Pulling active session tokens from Redis session cache...' },
            { level: 'INFO', message: '[RBAC] Auditing principle of least privilege across 1,248 identities...' },
            { level: 'WARN', message: '[AUDIT] 3 service accounts identified with unrotated credentials > 90 days...' },
            { level: 'INFO', message: 'Verifying authentication session integrity...' },
            { level: 'SUCCESS', message: '[MFA] 100% of administrative accounts verified with multi-factor tokens.' },
            { level: 'SUCCESS', message: '[POLICY] Role-Based Access Control matrix verified compliant.' },
        ];
    }
    else if (serviceName.toLowerCase().includes('audit')) {
        specificSteps = [
            { level: 'INFO', message: '[COMPLIANCE] Initiating SOC 2 Type II automated controls evaluation...' },
            { level: 'INFO', message: '[LOGS] Parsing immutable CloudWatch audit trails and SIEM event streams...' },
            { level: 'INFO', message: '[INTEGRITY] Validating SHA-256 HMAC checksums of server access logs...' },
            { level: 'WARN', message: '[RETENTION] Log retention policy set to 180 days (Recommended: 365 days)...' },
            { level: 'SUCCESS', message: '[BENCHMARK] CIS Benchmark Level 1 compliance score: 94.6%.' },
        ];
    }
    else if (serviceName.toLowerCase().includes('intrusion')) {
        specificSteps = [
            { level: 'INFO', message: '[IDS/IPS] Activating eBPF kernel network filter probes...' },
            { level: 'INFO', message: '[SURICATA] Loading Emerging Threats (ET) open rule definitions...' },
            { level: 'WARN', message: '[SUSPECT] Unusually high SYN packet frequency detected from ASN 14061...' },
            { level: 'INFO', message: '[MITIGATION] Applying dynamic rate-limiter penalty to suspicious IP range...' },
            { level: 'SUCCESS', message: '[SECURE] Threat neutralized. Ingress throughput normalized.' },
        ];
    }
    else if (serviceName.toLowerCase().includes('api')) {
        specificSteps = [
            { level: 'INFO', message: '[GATEWAY] Querying Express reverse-proxy middleware logs...' },
            { level: 'INFO', message: '[CORS] Verifying strict origin whitelisting against client origin...' },
            { level: 'INFO', message: '[HEADERS] Validating Helmet security headers (CSP, X-Frame-Options, HSTS)...' },
            { level: 'SUCCESS', message: '[HEALTH] API Latency P99: 14ms | Error Rate: 0.001% | Status: 200 OK.' },
        ];
    }
    else {
        specificSteps = [
            { level: 'INFO', message: '[CRYPTO] Inspecting TLS 1.3 negotiated cipher suites (AES-256-GCM)...' },
            { level: 'INFO', message: '[KEYSTORE] Checking KMS master key rotation schedule...' },
            { level: 'SUCCESS', message: '[AT-REST] MongoDB WiredTiger storage engine verified with AES-256 encryption.' },
            { level: 'SUCCESS', message: '[IN-TRANSIT] All HTTP endpoints strictly enforce HTTPS redirection.' },
        ];
    }
    const finalSteps = [
        { level: 'INFO', message: '[REPORT] Compiling structured vulnerability and compliance report...' },
        { level: 'SUCCESS', message: '[COMPLETE] Service run executed cleanly. Session telemetry finalized.' },
    ];
    return [...baseSteps, ...specificSteps, ...finalSteps];
};
let globalIoInstance = null;
const getSocketIO = () => globalIoInstance;
exports.getSocketIO = getSocketIO;
const emitLiveTrafficUpdate = (log) => {
    if (globalIoInstance) {
        globalIoInstance.emit('live-traffic-update', log);
    }
};
exports.emitLiveTrafficUpdate = emitLiveTrafficUpdate;
/**
 * Configure Socket.io with JWT Authentication Middleware and Real-Time Service Execution
 */
const setupSocketIO = (httpServer) => {
    const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
    const io = new socket_io_1.Server(httpServer, {
        cors: {
            origin: [clientUrl, 'http://localhost:3000', 'http://192.168.56.1:3000'],
            credentials: true,
            methods: ['GET', 'POST'],
        },
        transports: ['websocket', 'polling'],
    });
    globalIoInstance = io;
    // Track active intervals by socket ID to prevent memory leaks
    const activeIntervals = new Map();
    /**
     * WebSocket Authentication Middleware
     * Verifies the exact same JWT Access Token stored in HttpOnly cookies (or handshake auth)
     */
    io.use((socket, next) => {
        try {
            let token;
            // 1. Primary: Extract from HttpOnly cookie sent by browser with credentials
            const cookieHeader = socket.handshake.headers.cookie;
            if (cookieHeader) {
                const parsedCookies = parseRawCookieHeader(cookieHeader);
                token = parsedCookies.accessToken;
            }
            // 2. Fallback: Handshake auth token (e.g. For automated test clients)
            if (!token && socket.handshake.auth && socket.handshake.auth.token) {
                token = socket.handshake.auth.token;
            }
            if (!token) {
                console.warn(`[SOCKET AUTH REJECTED] Connection from ${socket.id} rejected: No access token.`);
                return next(new Error('Authentication required: Access token missing.'));
            }
            // Verify JWT signature & expiration
            const decoded = (0, jwt_util_1.verifyAccessToken)(token);
            socket.data = { user: decoded };
            return next();
        }
        catch (err) {
            console.warn(`[SOCKET AUTH REJECTED] Connection from ${socket.id} rejected: Invalid/Expired token:`, (err === null || err === void 0 ? void 0 : err.message) || err);
            return next(new Error('Authentication failed: Invalid or expired access token.'));
        }
    });
    io.on('connection', (socket) => {
        var _a, _b;
        const authSocket = socket;
        const userEmail = ((_b = (_a = authSocket.data) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.email) || 'authenticated-user';
        console.log(`🔌 [SOCKET CONNECTED] Client: ${socket.id} | User: ${userEmail}`);
        /**
         * Listener: start-service-execution
         * Simulates live security scanning via 800ms log streams and updates lastRun in MongoDB
         */
        socket.on('start-service-execution', (payload) => __awaiter(void 0, void 0, void 0, function* () {
            var _c, _d, _e, _f;
            try {
                const { serviceId, targetId } = payload;
                console.log(`🚀 [SERVICE RUN START] Client ${socket.id} initiated execution for service: ${serviceId} on target: ${targetId}`);
                // Cancel any existing run for this socket
                if (activeIntervals.has(socket.id)) {
                    clearInterval(activeIntervals.get(socket.id));
                    activeIntervals.delete(socket.id);
                }
                const target = yield target_model_1.TargetModel.findById(targetId);
                if (!target) {
                    socket.emit('log-update', {
                        level: 'ALERT',
                        message: `[ERROR] Target asset not found in database.`,
                    });
                    return;
                }
                socket.emit('log-update', {
                    level: 'INFO',
                    message: `[SYSTEM] Target lock acquired: ${target.host}`,
                });
                // Locate service in MongoDB
                let service = null;
                if (typeof serviceId === 'number' || !isNaN(Number(serviceId))) {
                    service = yield service_model_1.default.findOne({ serviceId: Number(serviceId) });
                }
                else {
                    service = yield service_model_1.default.findById(serviceId);
                }
                if (!service) {
                    socket.emit('execution-error', { error: `Security service "${serviceId}" was not found.` });
                    return;
                }
                const serviceName = service.name.toLowerCase();
                let findings = [];
                try {
                    if (serviceName.includes('vulnerability') || serviceName.includes('host')) {
                        socket.emit('log-update', { level: 'INFO', message: '[SYSTEM] Initiating Host-Based Intrusion Detection System (HIDS)...' });
                        // 1. System & Resource Audit
                        const sysFindings = yield (0, systemAuditor_1.auditSystem)(socket);
                        findings.push(...sysFindings);
                        // 2. File Integrity Monitoring (FIM)
                        // Hardcode path to prevent Directory Traversal
                        const safeFimDir = path_1.default.join(__dirname, '../model');
                        const fimFindings = yield (0, fileMonitor_1.checkFileIntegrity)(safeFimDir, socket);
                        findings.push(...fimFindings);
                        // 3. Malware Scanning (ClamAV)
                        const safeMalwareDir = path_1.default.join(__dirname, '../model');
                        const malwareFindings = yield (0, malwareScanner_1.scanForMalware)(safeMalwareDir, socket);
                        findings.push(...malwareFindings);
                    }
                    else if (serviceName.includes('port')) {
                        findings = yield (0, portScanner_1.scanPorts)(target.host, [21, 22, 80, 443, 3306, 27017], socket);
                    }
                    else if (serviceName.includes('security audits') || serviceName.includes('http header')) {
                        findings = yield (0, headerScanner_1.scanHeaders)(target.host, socket);
                    }
                    else {
                        // Default to header scan if not matched
                        findings = yield (0, headerScanner_1.scanHeaders)(target.host, socket);
                    }
                }
                catch (probeError) {
                    socket.emit('log-update', {
                        level: 'ALERT',
                        message: `[ERROR] Probe execution failed: ${probeError.message}`,
                    });
                    socket.emit('execution-error', { error: 'Probe unreachable or failed.' });
                    return;
                }
                const completionTime = new Date();
                service.lastRun = completionTime;
                service.status = 'Active';
                yield service.save();
                const scanReport = yield scanReport_model_1.ScanReportModel.create({
                    user: ((_d = (_c = authSocket.data) === null || _c === void 0 ? void 0 : _c.user) === null || _d === void 0 ? void 0 : _d.userId) || ((_f = (_e = authSocket.data) === null || _e === void 0 ? void 0 : _e.user) === null || _f === void 0 ? void 0 : _f._id) || target.user,
                    target: target._id,
                    service: service.name,
                    status: findings.length > 0 ? 'Warning' : 'Success',
                    findings: findings
                });
                console.log(`🏁 [SERVICE RUN FINISHED] Service ${service.name} completed on ${target.host}.`);
                socket.emit('scan-complete', {
                    serviceId: service.serviceId,
                    serviceName: service.name,
                    completedAt: completionTime.toISOString(),
                    status: 'Completed',
                    report: scanReport,
                });
            }
            catch (error) {
                console.error('Error during service execution:', error);
                socket.emit('execution-error', { error: 'Internal error running security service.' });
            }
        }));
        /**
         * Cleanup interval on disconnect to prevent memory leaks
         */
        socket.on('disconnect', (reason) => {
            console.log(`🔌 [SOCKET DISCONNECTED] Client: ${socket.id} | Reason: ${reason}`);
            if (activeIntervals.has(socket.id)) {
                clearInterval(activeIntervals.get(socket.id));
                activeIntervals.delete(socket.id);
            }
        });
    });
    return io;
};
exports.setupSocketIO = setupSocketIO;
