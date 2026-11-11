import { Request, Response } from 'express';
import net from 'net';
import axios from 'axios';
import AuditLogModel from '../model/auditLog.model';
import { getActorContext, getRequestId, recordAuditEvent } from '../services/auditService';

// ─── Types ────────────────────────────────────────────────────────────────────

interface PortScanResult {
  port: number;
  service: string;
  status: 'Open/Vulnerable' | 'Filtered/Secure' | 'Error';
  riskLevel: 'critical' | 'high' | 'low';
}

interface BrowserTelemetry {
  os: string;
  browser: string;
  browserVersion: string;
  isOutdated: boolean;
  protocol: string;
  isHttps: boolean;
  webrtcLeakedIp: string | null;
  screenResolution: string;
  timezone: string;
  webglRenderer: string;
  fingerprintScore: number;
}

interface AuditReport {
  timestamp: string;
  publicIp: string;
  telemetry: BrowserTelemetry;
  portScan: PortScanResult[];
  securityScore: number;
  recommendations: Array<{
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
  }>;
  summary: {
    openPorts: number;
    filteredPorts: number;
    privacyLeaks: number;
    overallRisk: 'Critical' | 'High' | 'Medium' | 'Low';
  };
}

// ─── Dangerous Ports Configuration ───────────────────────────────────────────

const DANGEROUS_PORTS: Array<{ port: number; service: string }> = [
  { port: 22,   service: 'SSH'                        },
  { port: 23,   service: 'Telnet'                     },
  { port: 80,   service: 'HTTP'                       },
  { port: 443,  service: 'HTTPS'                      },
  { port: 445,  service: 'SMB (Windows File Sharing)' },
  { port: 3389, service: 'RDP (Remote Desktop)'       },
  { port: 3306, service: 'MySQL'                      },
  { port: 5432, service: 'PostgreSQL'                 },
  { port: 8080, service: 'HTTP Alternate'             },
  { port: 8443, service: 'HTTPS Alternate'            },
];

// FIX: Reduced timeout so all 10 parallel scans finish well within the 35s client timeout.
// 10 ports × 2000ms timeout = at most 2s total (they run in parallel), plus overhead.
const PORT_SCAN_TIMEOUT_MS = 2000;

// ─── Port Scanner Utility ─────────────────────────────────────────────────────

/**
 * Attempts a TCP connection to host:port.
 * - connect event  → Open/Vulnerable
 * - timeout event  → Filtered/Secure (NAT/Firewall dropping silently)
 * - ECONNREFUSED   → Filtered/Secure (host up, port closed by firewall/OS)
 * - Any other error → Error (network unreachable, bad IP, etc.)
 *
 * FIX: Added a hard Promise-level timeout wrapper as a safety net in case
 * the net.Socket events fail to fire (can happen on Windows with certain
 * network configurations / VPNs), preventing the controller from hanging.
 */
function scanPort(host: string, port: number): Promise<PortScanResult> {
  const serviceEntry = DANGEROUS_PORTS.find(p => p.port === port);
  const service = serviceEntry?.service ?? `Port ${port}`;

  const riskMap: Record<number, 'critical' | 'high' | 'low'> = {
    23:   'critical',
    3389: 'critical',
    445:  'critical',
    22:   'high',
    3306: 'high',
    5432: 'high',
    80:   'low',
    443:  'low',
    8080: 'low',
    8443: 'low',
  };

  const riskLevel = riskMap[port] ?? 'low';

  // FIX: Wrap the entire socket operation in a hard timeout that is 500ms
  // longer than PORT_SCAN_TIMEOUT_MS. This ensures we ALWAYS resolve, even
  // if the socket event-loop somehow stalls (seen on Windows + VPN setups).
  const HARD_TIMEOUT_MS = PORT_SCAN_TIMEOUT_MS + 500;

  const scanPromise = new Promise<PortScanResult>((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const settle = (result: PortScanResult) => {
      if (!resolved) {
        resolved = true;
        try { socket.destroy(); } catch {}
        resolve(result);
      }
    };

    socket.setTimeout(PORT_SCAN_TIMEOUT_MS);

    socket.on('connect', () => settle({ port, service, status: 'Open/Vulnerable', riskLevel }));

    socket.on('timeout', () => settle({ port, service, status: 'Filtered/Secure', riskLevel }));

    socket.on('error', (err: NodeJS.ErrnoException) => {
      // ECONNREFUSED  = host responded but rejected → effectively secure
      // ENETUNREACH   = no route to host → IP is offline or firewalled
      // EHOSTUNREACH  = host unreachable at network level
      const secureErrorCodes = ['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNRESET'];
      if (err.code && secureErrorCodes.includes(err.code)) {
        settle({ port, service, status: 'Filtered/Secure', riskLevel });
      } else {
        settle({ port, service, status: 'Error', riskLevel });
      }
    });

    // FIX: socket.connect() can throw synchronously on Windows when the host
    // string is invalid (e.g. '0.0.0.0'). Wrap in try/catch.
    try {
      socket.connect(port, host);
    } catch (syncErr) {
      settle({ port, service, status: 'Error', riskLevel });
    }
  });

  // Hard safety-net timeout — always resolves as Filtered if socket stalls.
  const hardTimeoutPromise = new Promise<PortScanResult>((resolve) =>
    setTimeout(
      () => resolve({ port, service, status: 'Filtered/Secure', riskLevel }),
      HARD_TIMEOUT_MS
    )
  );

  return Promise.race([scanPromise, hardTimeoutPromise]);
}

// ─── Threat Analysis Engine ────────────────────────────────────────────────────

function generateRecommendations(
  telemetry: BrowserTelemetry,
  portResults: PortScanResult[]
): AuditReport['recommendations'] {
  const recs: AuditReport['recommendations'] = [];

  for (const result of portResults) {
    if (result.status !== 'Open/Vulnerable') continue;

    if (result.port === 3389) {
      recs.push({
        id: 'rdp-exposed',
        severity: 'critical',
        title: 'Remote Desktop Protocol (RDP) Exposed to Internet',
        description:
          'CRITICAL: Port 3389 (RDP) is reachable from the public internet. This is a primary vector for ransomware and brute-force attacks. Immediately configure your router/firewall to block external access to port 3389. Use a VPN for remote access instead.',
      });
    }
    if (result.port === 445) {
      recs.push({
        id: 'smb-exposed',
        severity: 'critical',
        title: 'SMB Port Exposed — Ransomware Vector',
        description:
          'CRITICAL: Port 445 (SMB/Windows File Sharing) is publicly accessible. This is the attack vector exploited by WannaCry and NotPetya ransomware. Block this port on your router firewall immediately for all external traffic.',
      });
    }
    if (result.port === 23) {
      recs.push({
        id: 'telnet-exposed',
        severity: 'critical',
        title: 'Telnet Service Detected — Unencrypted Protocol',
        description:
          'Port 23 (Telnet) transmits all data including credentials in plaintext. Disable Telnet immediately and replace with SSH. No modern system should use Telnet.',
      });
    }
    if (result.port === 22) {
      recs.push({
        id: 'ssh-exposed',
        severity: 'high',
        title: 'SSH Port Publicly Accessible',
        description:
          'Port 22 (SSH) is open to the internet and exposed to automated brute-force attacks. Restrict SSH access by IP using firewall rules, disable password authentication in favor of SSH keys, and consider using a non-standard port.',
      });
    }
    if (result.port === 3306) {
      recs.push({
        id: 'mysql-exposed',
        severity: 'high',
        title: 'MySQL Database Exposed to Internet',
        description:
          'Port 3306 (MySQL) should never be directly accessible from the public internet. Bind the MySQL service to localhost and use an SSH tunnel or VPN for remote database access.',
      });
    }
    if (result.port === 5432) {
      recs.push({
        id: 'postgres-exposed',
        severity: 'high',
        title: 'PostgreSQL Database Exposed to Internet',
        description:
          'Port 5432 (PostgreSQL) is publicly accessible. Databases should never be directly reachable from the internet. Bind to localhost and use a secure tunnel for remote access.',
      });
    }
  }

  if (telemetry.isOutdated) {
    recs.push({
      id: 'outdated-browser',
      severity: 'high',
      title: 'Browser Version Appears Outdated',
      description:
        'Your browser version may contain known CVEs (Common Vulnerabilities and Exposures). Update your browser to the latest stable version immediately to patch critical security vulnerabilities.',
    });
  }

  if (!telemetry.isHttps) {
    recs.push({
      id: 'insecure-http',
      severity: 'high',
      title: 'Accessing Dashboard Over Insecure HTTP',
      description:
        'Your connection is not encrypted. Data transmitted over HTTP can be intercepted by anyone on the same network (MITM attack). Ensure this application is served over HTTPS with a valid TLS certificate.',
    });
  }

  if (telemetry.webrtcLeakedIp) {
    recs.push({
      id: 'webrtc-leak',
      severity: 'medium',
      title: 'WebRTC Local IP Address Leaked',
      description: `WebRTC has exposed your internal LAN IP address (${telemetry.webrtcLeakedIp}). This can reveal your network topology even behind a VPN. Disable WebRTC in browser settings or use a WebRTC leak prevention extension. Consider a VPN with WebRTC leak protection.`,
    });
  }

  if (telemetry.fingerprintScore >= 75) {
    recs.push({
      id: 'high-fingerprint',
      severity: 'medium',
      title: 'Browser is Highly Fingerprintable',
      description:
        'Your browser exposes unique characteristics (screen resolution, timezone, WebGL renderer) that allow websites to track you without cookies. Use Firefox with privacy.resistFingerprinting enabled, or the Tor Browser, to reduce your fingerprinting surface.',
    });
  }

  const openHighRisk = portResults.filter(
    r => r.status === 'Open/Vulnerable' && (r.riskLevel === 'critical' || r.riskLevel === 'high')
  );
  if (openHighRisk.length === 0) {
    recs.push({
      id: 'firewall-good',
      severity: 'low',
      title: 'Firewall Is Blocking High-Risk Ports',
      description:
        'No critical or high-risk ports are publicly accessible from your network. Your firewall and NAT configuration appear to be working correctly. Continue to perform regular audits.',
    });
  }

  return recs;
}

function calculateSecurityScore(telemetry: BrowserTelemetry, portResults: PortScanResult[]): number {
  let score = 100;

  for (const result of portResults) {
    if (result.status !== 'Open/Vulnerable') continue;
    if (result.riskLevel === 'critical') score -= 25;
    else if (result.riskLevel === 'high') score -= 15;
    else score -= 3;
  }

  if (telemetry.isOutdated)             score -= 15;
  if (!telemetry.isHttps)               score -= 10;
  if (telemetry.webrtcLeakedIp)         score -= 10;
  if (telemetry.fingerprintScore >= 75) score -= 5;
  if (telemetry.fingerprintScore >= 90) score -= 5;

  return Math.max(0, score);
}

// ─── Public IP Resolution ──────────────────────────────────────────────────────

/**
 * Determines if an IP string is a private/loopback/link-local address.
 * FIX: Added 172.16-31.x range which was missing, causing some local
 * Docker/VPN addresses to be mistakenly treated as public IPs.
 */
function isPrivateOrLocalIp(ip: string): boolean {
  if (!ip) return true;
  if (ip === '::1') return true;
  if (ip.startsWith('127.')) return true;          // Loopback
  if (ip.startsWith('10.')) return true;            // RFC 1918
  if (ip.startsWith('192.168.')) return true;       // RFC 1918
  if (ip.startsWith('169.254.')) return true;       // Link-local
  if (ip.startsWith('0.')) return true;             // Invalid
  // RFC 1918 172.16.0.0/12 range
  const parts = ip.split('.');
  if (parts.length === 4 && parts[0] === '172') {
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

async function resolvePublicIp(req: Request): Promise<string> {
  // 1. X-Forwarded-For header (reverse proxy / load balancer)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const firstIp = (Array.isArray(forwarded) ? forwarded[0] : forwarded)
      .split(',')[0]
      .trim()
      .replace('::ffff:', '');
    if (firstIp && !isPrivateOrLocalIp(firstIp)) {
      console.log(`[AuditController] IP from X-Forwarded-For: ${firstIp}`);
      return firstIp;
    }
  }

  // 2. Direct socket remote address
  const remoteAddr = (req.socket?.remoteAddress ?? '').replace('::ffff:', '');
  if (remoteAddr && !isPrivateOrLocalIp(remoteAddr)) {
    console.log(`[AuditController] IP from socket: ${remoteAddr}`);
    return remoteAddr;
  }

  // 3. Fallback: external IP service (development / localhost scenario)
  console.log('[AuditController] Local/private IP detected, falling back to ipify.org...');
  try {
    const { data } = await axios.get<{ ip: string }>('https://api.ipify.org?format=json', {
      timeout: 6000,
    });
    if (data?.ip && !isPrivateOrLocalIp(data.ip)) {
      console.log(`[AuditController] IP from ipify: ${data.ip}`);
      return data.ip;
    }
  } catch (e1) {
    console.warn('[AuditController] ipify primary failed, trying backup...');
    try {
      const { data } = await axios.get<{ ip: string }>('https://api64.ipify.org?format=json', {
        timeout: 6000,
      });
      if (data?.ip && !isPrivateOrLocalIp(data.ip)) {
        console.log(`[AuditController] IP from ipify backup: ${data.ip}`);
        return data.ip;
      }
    } catch (e2) {
      console.error('[AuditController] Both ipify endpoints failed:', e2);
    }
  }

  // Complete fallback — scan will produce all "Error" results but won't crash
  console.warn('[AuditController] Could not resolve public IP, using 127.0.0.1 as safe fallback');
  return '127.0.0.1';
}

// ─── Audit log listing / retrieval ──────────────────────────────────────────

const allowedAuditFilters = ['category', 'action', 'status', 'severity', 'resourceType'];

const parsePagination = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const buildAuditQuery = (req: Request) => {
  const { category, action, status, severity, actor, resourceType, startDate, endDate, search } = req.query;
  const query: Record<string, any> = {};

  if (typeof category === 'string' && category.trim()) query.category = category.trim();
  if (typeof action === 'string' && action.trim()) query.action = new RegExp(action.trim(), 'i');
  if (typeof status === 'string' && status.trim()) query.status = status.trim();
  if (typeof severity === 'string' && severity.trim()) query.severity = severity.trim();
  if (typeof resourceType === 'string' && resourceType.trim()) query.resourceType = resourceType.trim();
  if (typeof actor === 'string' && actor.trim()) query.actorId = actor.trim();

  if (typeof startDate === 'string' && startDate.trim()) {
    query.timestamp = { ...(query.timestamp || {}), $gte: new Date(startDate) };
  }
  if (typeof endDate === 'string' && endDate.trim()) {
    query.timestamp = { ...(query.timestamp || {}), $lte: new Date(endDate) };
  }

  if (typeof search === 'string' && search.trim()) {
    const sanitized = search.trim();
    query.$or = [
      { action: new RegExp(sanitized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') },
      { eventId: new RegExp(sanitized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') },
      { source: new RegExp(sanitized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') },
    ];
  }

  return query;
};

export const listAuditLogs = async (req: Request, res: Response): Promise<void> => {
  try {
    const page = parsePagination(req.query.page, 1);
    const limit = Math.min(parsePagination(req.query.limit, 10), 50);
    const skip = (page - 1) * limit;
    const query = buildAuditQuery(req);
    if (req.user?.role !== 'admin') {
      query.actorId = req.user?.userId;
    }

    const [events, total, summary] = await Promise.all([
      AuditLogModel.find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      AuditLogModel.countDocuments(query),
      AuditLogModel.aggregate([
        { $match: query },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            success: { $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] } },
            failure: { $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] } },
            denied: { $sum: { $cond: [{ $eq: ['$status', 'denied'] }, 1, 0] } },
            highSeverity: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
            criticalSeverity: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
          },
        },
      ]),
    ]);

    const summaryRow = summary[0] || {
      total: 0,
      success: 0,
      failure: 0,
      denied: 0,
      highSeverity: 0,
      criticalSeverity: 0,
    };

    res.status(200).json({
      events: events.map((event) => ({
        ...event,
        id: event._id?.toString?.() || event.eventId,
        timestamp: event.timestamp instanceof Date ? event.timestamp.toISOString() : event.timestamp,
      })),
      summary: {
        total: summaryRow.total,
        success: summaryRow.success,
        failure: summaryRow.failure,
        denied: summaryRow.denied,
        highSeverity: summaryRow.highSeverity + summaryRow.criticalSeverity,
        period: {
          start: req.query.startDate || null,
          end: req.query.endDate || null,
        },
      },
      pagination: {
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit)),
        totalItems: total,
      },
    });
  } catch (error: any) {
    console.error('Audit list error:', error);
    res.status(500).json({ error: 'Unable to load audit records.' });
  }
};

export const getAuditLogById = async (req: Request, res: Response): Promise<void> => {
  try {
    if (req.user?.role !== 'admin') {
      res.status(403).json({ error: 'Only administrators can access audit logs.' });
      return;
    }

    const { id } = req.params;
    const event = await AuditLogModel.findOne({ $or: [{ _id: id }, { eventId: id }] }).lean();

    if (!event) {
      res.status(404).json({ error: 'Audit record not found.' });
      return;
    }

    res.status(200).json({
      event: {
        ...event,
        id: event._id?.toString?.() || event.eventId,
        timestamp: event.timestamp instanceof Date ? event.timestamp.toISOString() : event.timestamp,
      },
    });
  } catch (error: any) {
    console.error('Audit detail error:', error);
    res.status(500).json({ error: 'Unable to load the selected audit record.' });
  }
};

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /api/audits/client
 *
 * Accepts browser telemetry, resolves the client's public IP from the
 * request context, runs a parallel port scan, generates threat analysis,
 * and returns a full AuditReport JSON object.
 */
export const runClientAudit = async (req: Request, res: Response): Promise<void> => {
  const requestId = getRequestId(req);
  const actor = getActorContext(req);
  try {
    const telemetry: BrowserTelemetry = req.body?.telemetry;

    if (!telemetry) {
      await recordAuditEvent({
        action: 'system_audit_rejected',
        category: 'security scan',
        status: 'denied',
        severity: 'low',
        source: 'system_audit',
        requestId,
        ...actor,
        metadata: { reason: 'missing_telemetry' },
        errorCode: 'MISSING_TELEMETRY',
      });
      res.status(400).json({ error: 'Telemetry payload is required.' });
      return;
    }

    await recordAuditEvent({
      action: 'system_audit_requested',
      category: 'security scan',
      source: 'system_audit',
      requestId,
      ...actor,
      resourceType: 'client_environment',
      metadata: { browser: telemetry.browser, os: telemetry.os },
    });

    console.log('[AuditController] Starting client environment audit...');

    // 1. Resolve public IP
    const publicIp = await resolvePublicIp(req);
    console.log(`[AuditController] Target IP for port scan: ${publicIp}`);

    // 2. Run all port scans in parallel (each has its own timeout, so this
    //    takes at most PORT_SCAN_TIMEOUT_MS + 500ms regardless of port count)
    console.log(`[AuditController] Scanning ${DANGEROUS_PORTS.length} ports in parallel...`);
    const portScanResults = await Promise.all(
      DANGEROUS_PORTS.map(({ port }) => scanPort(publicIp, port))
    );

    const openCount = portScanResults.filter(r => r.status === 'Open/Vulnerable').length;
    console.log(`[AuditController] Scan done. Open: ${openCount}, Filtered: ${portScanResults.length - openCount}`);

    // 3. Threat analysis
    const recommendations = generateRecommendations(telemetry, portScanResults);
    const securityScore = calculateSecurityScore(telemetry, portScanResults);

    // 4. Determine overall risk level
    const criticalOpen = portScanResults.filter(r => r.status === 'Open/Vulnerable' && r.riskLevel === 'critical').length;
    const highOpen     = portScanResults.filter(r => r.status === 'Open/Vulnerable' && r.riskLevel === 'high').length;
    const privacyLeaks = (telemetry.webrtcLeakedIp ? 1 : 0) + (!telemetry.isHttps ? 1 : 0);

    let overallRisk: AuditReport['summary']['overallRisk'];
    if (securityScore < 40 || criticalOpen > 0) overallRisk = 'Critical';
    else if (securityScore < 60 || highOpen > 0) overallRisk = 'High';
    else if (securityScore < 80)                 overallRisk = 'Medium';
    else                                         overallRisk = 'Low';

    // 5. Assemble and return the report
    const report: AuditReport = {
      timestamp: new Date().toISOString(),
      publicIp,
      telemetry,
      portScan: portScanResults,
      securityScore,
      recommendations,
      summary: {
        openPorts:     openCount,
        filteredPorts: portScanResults.filter(r => r.status === 'Filtered/Secure').length,
        privacyLeaks,
        overallRisk,
      },
    };
    await recordAuditEvent({
      action: 'system_audit_completed',
      category: 'security scan',
      source: 'system_audit',
      requestId,
      ...actor,
      resourceType: 'client_environment',
      severity: overallRisk === 'Critical' ? 'critical' : overallRisk === 'High' ? 'high' : overallRisk === 'Medium' ? 'medium' : 'low',
      metadata: { publicIp, securityScore, overallRisk, openPorts: openCount, privacyLeaks },
    });
    console.log(`[AuditController] Report ready. Score: ${securityScore}/100, Risk: ${overallRisk}`);
    res.status(200).json(report);
  } catch (error: any) {
    console.error('[AuditController] Unhandled error during audit:', error);
    await recordAuditEvent({
      action: 'system_audit_failed',
      category: 'security scan',
      status: 'failure',
      severity: 'high',
      source: 'system_audit',
      requestId,
      ...actor,
      metadata: { reason: 'audit_execution_error' },
      errorCode: 'AUDIT_EXECUTION_ERROR',
    });
    res.status(500).json({ error: 'An internal error occurred during the security audit.' });
  }
};
