import { Server as HttpServer } from 'http';
import { Server, Socket } from 'socket.io';
import { verifyAccessToken, TokenUserPayload } from '../util/jwt.util';
import ServiceModel, { IService } from '../model/service.model';
import { TargetModel } from '../model/target.model';
import { ScanReportModel } from '../model/scanReport.model';
import { scanPorts } from '../scanners/portScanner';
import { scanHeaders } from '../scanners/headerScanner';
import { auditSystem } from '../scanners/systemAuditor';
import { checkFileIntegrity } from '../scanners/fileMonitor';
import { scanForMalware } from '../scanners/malwareScanner';
import path from 'path';

const parseRawCookieHeader = (rawCookie?: string): Record<string, string> => {
  if (!rawCookie) return {};
  const result: Record<string, string> = {};
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

export interface AuthenticatedSocket extends Socket {
  data: {
    user?: TokenUserPayload;
  };
}

/**
 * Generate rich, realistic security terminal logs tailored to each service
 */
const generateLogsForService = (serviceName: string): Array<{ level: 'INFO' | 'WARN' | 'SUCCESS' | 'ALERT'; message: string }> => {
  const baseSteps = [
    { level: 'INFO' as const, message: `[SYSTEM] Initializing telemetry runtime for ${serviceName}...` },
    { level: 'INFO' as const, message: '[AUTH] Validating analyst credentials and JWT session signatures...' },
    { level: 'INFO' as const, message: '[NETWORK] Binding ephemeral socket to target sandbox container...' },
  ];

  let specificSteps: Array<{ level: 'INFO' | 'WARN' | 'SUCCESS' | 'ALERT'; message: string }> = [];

  if (serviceName.toLowerCase().includes('vulnerability')) {
    specificSteps = [
      { level: 'INFO' as const, message: '[SCAN] Loading NVD (National Vulnerability Database) feed v2026.10...' },
      { level: 'INFO' as const, message: '[PROBE] Executing passive TCP SYN port sweep across ports 1-65535...' },
      { level: 'WARN' as const, message: '[WARN] Open non-standard listener detected on port 9200 (Elasticsearch cluster)...' },
      { level: 'INFO' as const, message: '[CURL] Simulating HTTP Header injection: testing Host, X-Forwarded-For...' },
      { level: 'ALERT' as const, message: '[CVE-2024-3400] Scanning telemetry interface for arbitrary command execution...' },
      { level: 'WARN' as const, message: '[FINDING] Subresource Integrity (SRI) missing on 2 external CDN scripts...' },
      { level: 'INFO' as const, message: '[DEPS] Inspecting npm dependency tree for vulnerable transitive packages...' },
      { level: 'SUCCESS' as const, message: '[PATCH] 0 critical RCE exploits found. 24 medium warnings cataloged.' },
    ];
  } else if (serviceName.toLowerCase().includes('access')) {
    specificSteps = [
      { level: 'INFO' as const, message: '[IAM] Pulling active session tokens from Redis session cache...' },
      { level: 'INFO' as const, message: '[RBAC] Auditing principle of least privilege across 1,248 identities...' },
      { level: 'WARN' as const, message: '[AUDIT] 3 service accounts identified with unrotated credentials > 90 days...' },
      { level: 'INFO' as const, message: 'Verifying authentication session integrity...' },
      { level: 'SUCCESS' as const, message: '[MFA] 100% of administrative accounts verified with multi-factor tokens.' },
      { level: 'SUCCESS' as const, message: '[POLICY] Role-Based Access Control matrix verified compliant.' },
    ];
  } else if (serviceName.toLowerCase().includes('audit')) {
    specificSteps = [
      { level: 'INFO' as const, message: '[COMPLIANCE] Initiating SOC 2 Type II automated controls evaluation...' },
      { level: 'INFO' as const, message: '[LOGS] Parsing immutable CloudWatch audit trails and SIEM event streams...' },
      { level: 'INFO' as const, message: '[INTEGRITY] Validating SHA-256 HMAC checksums of server access logs...' },
      { level: 'WARN' as const, message: '[RETENTION] Log retention policy set to 180 days (Recommended: 365 days)...' },
      { level: 'SUCCESS' as const, message: '[BENCHMARK] CIS Benchmark Level 1 compliance score: 94.6%.' },
    ];
  } else if (serviceName.toLowerCase().includes('intrusion')) {
    specificSteps = [
      { level: 'INFO' as const, message: '[IDS/IPS] Activating eBPF kernel network filter probes...' },
      { level: 'INFO' as const, message: '[SURICATA] Loading Emerging Threats (ET) open rule definitions...' },
      { level: 'WARN' as const, message: '[SUSPECT] Unusually high SYN packet frequency detected from ASN 14061...' },
      { level: 'INFO' as const, message: '[MITIGATION] Applying dynamic rate-limiter penalty to suspicious IP range...' },
      { level: 'SUCCESS' as const, message: '[SECURE] Threat neutralized. Ingress throughput normalized.' },
    ];
  } else if (serviceName.toLowerCase().includes('api')) {
    specificSteps = [
      { level: 'INFO' as const, message: '[GATEWAY] Querying Express reverse-proxy middleware logs...' },
      { level: 'INFO' as const, message: '[CORS] Verifying strict origin whitelisting against client origin...' },
      { level: 'INFO' as const, message: '[HEADERS] Validating Helmet security headers (CSP, X-Frame-Options, HSTS)...' },
      { level: 'SUCCESS' as const, message: '[HEALTH] API Latency P99: 14ms | Error Rate: 0.001% | Status: 200 OK.' },
    ];
  } else {
    specificSteps = [
      { level: 'INFO' as const, message: '[CRYPTO] Inspecting TLS 1.3 negotiated cipher suites (AES-256-GCM)...' },
      { level: 'INFO' as const, message: '[KEYSTORE] Checking KMS master key rotation schedule...' },
      { level: 'SUCCESS' as const, message: '[AT-REST] MongoDB WiredTiger storage engine verified with AES-256 encryption.' },
      { level: 'SUCCESS' as const, message: '[IN-TRANSIT] All HTTP endpoints strictly enforce HTTPS redirection.' },
    ];
  }

  const finalSteps = [
    { level: 'INFO' as const, message: '[REPORT] Compiling structured vulnerability and compliance report...' },
    { level: 'SUCCESS' as const, message: '[COMPLETE] Service run executed cleanly. Session telemetry finalized.' },
  ];

  return [...baseSteps, ...specificSteps, ...finalSteps];
};

let globalIoInstance: Server | null = null;

export const getSocketIO = (): Server | null => globalIoInstance;

export const emitLiveTrafficUpdate = (log: any) => {
  if (globalIoInstance) {
    globalIoInstance.emit('live-traffic-update', log);
  }
};

/**
 * Configure Socket.io with JWT Authentication Middleware and Real-Time Service Execution
 */
export const setupSocketIO = (httpServer: HttpServer): Server => {
  const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';

  const io = new Server(httpServer, {
    cors: {
      origin: [clientUrl, 'http://localhost:3000', 'http://192.168.56.1:3000'],
      credentials: true,
      methods: ['GET', 'POST'],
    },
    transports: ['websocket', 'polling'],
  });

  globalIoInstance = io;

  // Track active intervals by socket ID to prevent memory leaks
  const activeIntervals = new Map<string, NodeJS.Timeout>();

  /**
   * WebSocket Authentication Middleware
   * Verifies the exact same JWT Access Token stored in HttpOnly cookies (or handshake auth)
   */
  io.use((socket: Socket, next) => {
    try {
      let token: string | undefined;

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
      const decoded = verifyAccessToken(token);
      (socket as AuthenticatedSocket).data = { user: decoded };

      return next();
    } catch (err: any) {
      console.warn(`[SOCKET AUTH REJECTED] Connection from ${socket.id} rejected: Invalid/Expired token:`, err?.message || err);
      return next(new Error('Authentication failed: Invalid or expired access token.'));
    }
  });

  io.on('connection', (socket: Socket) => {
    const authSocket = socket as AuthenticatedSocket;
    const userEmail = authSocket.data?.user?.email || 'authenticated-user';

    console.log(`🔌 [SOCKET CONNECTED] Client: ${socket.id} | User: ${userEmail}`);

    /**
     * Listener: start-service-execution
     * Simulates live security scanning via 800ms log streams and updates lastRun in MongoDB
     */
    socket.on('start-service-execution', async (payload: { serviceId: string | number, targetId: string }) => {
      try {
        const { serviceId, targetId } = payload;
        console.log(`🚀 [SERVICE RUN START] Client ${socket.id} initiated execution for service: ${serviceId} on target: ${targetId}`);

        // Cancel any existing run for this socket
        if (activeIntervals.has(socket.id)) {
          clearInterval(activeIntervals.get(socket.id)!);
          activeIntervals.delete(socket.id);
        }

        const target = await TargetModel.findById(targetId);
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
        let service: IService | null = null;
        if (typeof serviceId === 'number' || !isNaN(Number(serviceId))) {
          service = await ServiceModel.findOne({ serviceId: Number(serviceId) });
        } else {
          service = await ServiceModel.findById(serviceId);
        }

        if (!service) {
          socket.emit('execution-error', { error: `Security service "${serviceId}" was not found.` });
          return;
        }

        const serviceName = service.name.toLowerCase();
        let findings: any[] = [];
        
        try {
          if (serviceName.includes('vulnerability') || serviceName.includes('host')) {
            socket.emit('log-update', { level: 'INFO', message: '[SYSTEM] Initiating Host-Based Intrusion Detection System (HIDS)...' });
            
            // 1. System & Resource Audit
            const sysFindings = await auditSystem(socket);
            findings.push(...sysFindings);

            // 2. File Integrity Monitoring (FIM)
            // Hardcode path to prevent Directory Traversal
            const safeFimDir = path.join(__dirname, '../model'); 
            const fimFindings = await checkFileIntegrity(safeFimDir, socket);
            findings.push(...fimFindings);

            // 3. Malware Scanning (ClamAV)
            const safeMalwareDir = path.join(__dirname, '../model');
            const malwareFindings = await scanForMalware(safeMalwareDir, socket);
            findings.push(...malwareFindings);

          } else if (serviceName.includes('port')) {
            findings = await scanPorts(target.host, [21, 22, 80, 443, 3306, 27017], socket);
          } else if (serviceName.includes('security audits') || serviceName.includes('http header')) {
            findings = await scanHeaders(target.host, socket);
          } else {
            // Default to header scan if not matched
            findings = await scanHeaders(target.host, socket);
          }
        } catch (probeError: any) {
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
        await service.save();

        const scanReport = await ScanReportModel.create({
          user: authSocket.data?.user?.userId || (authSocket.data?.user as any)?._id || target.user,
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

      } catch (error) {
        console.error('Error during service execution:', error);
        socket.emit('execution-error', { error: 'Internal error running security service.' });
      }
    });

    /**
     * Cleanup interval on disconnect to prevent memory leaks
     */
    socket.on('disconnect', (reason) => {
      console.log(`🔌 [SOCKET DISCONNECTED] Client: ${socket.id} | Reason: ${reason}`);
      if (activeIntervals.has(socket.id)) {
        clearInterval(activeIntervals.get(socket.id)!);
        activeIntervals.delete(socket.id);
      }
    });
  });

  return io;
};
