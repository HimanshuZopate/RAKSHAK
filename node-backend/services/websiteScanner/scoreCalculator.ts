import { ValidatedTarget } from './ssrfProtection';
import { TlsScanResult } from './tlsScanner';
import { HeaderScanResult } from './headerScanner';

export interface DetailedFinding {
  id: string;
  category: 'HTTPS & Transport' | 'TLS Certificate' | 'Security Headers' | 'Server Configuration';
  name: string;
  observed: string;
  status: 'Passed' | 'Needs Review' | 'Warning' | 'Unable to Verify';
  importance: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  whyItMatters: string;
  remediation: string;
}

export interface SecurityScoreBreakdown {
  score: number;
  label: 'Grade A' | 'Grade B' | 'Grade C' | 'Grade D' | 'Grade F';
  disclaimer: string;
  formula: {
    httpsPoints: number;
    tlsPoints: number;
    redirectPoints: number;
    hstsPoints: number;
    cspPoints: number;
    xctoPoints: number;
    framingPoints: number;
    referrerPoints: number;
    permissionsPoints: number;
    totalPossible: number;
  };
}

export interface AggregatedScanReport {
  target: {
    originalUrl: string;
    normalizedUrl: string;
    hostname: string;
    ipAddress: string;
    finalUrl: string;
  };
  scanTimestamp: string;
  scanStatus: 'Completed' | 'Partial' | 'Failed';
  summary: {
    completedChecks: number;
    unverifiedChecks: number;
    totalFindings: number;
    passedCount: number;
    reviewCount: number;
    warningCount: number;
  };
  scoreBreakdown: SecurityScoreBreakdown;
  overviewCards: {
    httpsSecurity: {
      status: 'green' | 'amber' | 'red' | 'gray';
      title: string;
      subtitle: string;
    };
    tlsCertificate: {
      status: 'green' | 'amber' | 'red' | 'gray';
      title: string;
      subtitle: string;
    };
    securityHeaders: {
      status: 'green' | 'amber' | 'red' | 'gray';
      title: string;
      subtitle: string;
    };
    configuration: {
      status: 'green' | 'amber' | 'red' | 'gray';
      title: string;
      subtitle: string;
    };
  };
  tlsDetails: TlsScanResult;
  headerDetails: HeaderScanResult;
  findings: DetailedFinding[];
  remediationGuidance: string[];
}

export const aggregateScanResults = (
  target: ValidatedTarget,
  tlsResult: TlsScanResult,
  headerResult: HeaderScanResult
): AggregatedScanReport => {
  const findings: DetailedFinding[] = [];
  const remediationGuidance: string[] = [];

  let completedChecks = 0;
  let unverifiedChecks = 0;

  // ── 1. Evaluate HTTPS Availability ──────────────────────────────────────────
  completedChecks++;
  if (headerResult.httpsAvailable) {
    findings.push({
      id: 'https-available',
      category: 'HTTPS & Transport',
      name: 'HTTPS Transport Availability',
      observed: `${headerResult.httpsStatus} (HTTP ${headerResult.httpsStatusCode || 200})`,
      status: 'Passed',
      importance: 'Critical',
      whyItMatters: 'HTTPS provides transport layer encryption, protecting credentials and data from wiretapping.',
      remediation: 'Keep HTTPS active across all routes and subdomains.',
    });
  } else {
    findings.push({
      id: 'https-available',
      category: 'HTTPS & Transport',
      name: 'HTTPS Transport Availability',
      observed: headerResult.httpsStatus,
      status: 'Warning',
      importance: 'Critical',
      whyItMatters: 'Unencrypted HTTP transmits credentials, cookies, and sensitive payloads in cleartext.',
      remediation: 'Provision a valid TLS certificate and configure web server listeners on port 443.',
    });
    remediationGuidance.push('Enable HTTPS immediately to encrypt data in transit and protect user confidentiality.');
  }

  // ── 2. Evaluate HTTP-to-HTTPS Redirection ───────────────────────────────────
  completedChecks++;
  if (headerResult.httpToHttpsRedirect) {
    findings.push({
      id: 'http-redirect',
      category: 'HTTPS & Transport',
      name: 'HTTP-to-HTTPS Redirection',
      observed: 'Port 80 automatically redirects to HTTPS',
      status: 'Passed',
      importance: 'High',
      whyItMatters: 'Prevents users from accidentally browsing or logging into insecure HTTP URLs.',
      remediation: 'Maintain 301 Permanent Redirect on port 80.',
    });
  } else {
    findings.push({
      id: 'http-redirect',
      category: 'HTTPS & Transport',
      name: 'HTTP-to-HTTPS Redirection',
      observed: 'No automatic redirect observed on port 80',
      status: 'Needs Review',
      importance: 'High',
      whyItMatters: 'Visitors typing the plain domain without "https://" might remain on an unencrypted HTTP connection.',
      remediation: 'Configure an HTTP 301 Permanent Redirect on port 80 forwarding all requests to https://.',
    });
    remediationGuidance.push('Configure your web server (Nginx/Apache/Cloudflare) to automatically redirect all port 80 HTTP traffic to HTTPS.');
  }

  // ── 3. Evaluate TLS Certificate ─────────────────────────────────────────────
  if (tlsResult.available) {
    completedChecks++;
    if (tlsResult.isExpired) {
      findings.push({
        id: 'tls-validity',
        category: 'TLS Certificate',
        name: 'TLS Certificate Expiration',
        observed: `Expired on ${tlsResult.validTo || 'Unknown'}`,
        status: 'Warning',
        importance: 'Critical',
        whyItMatters: 'Expired certificates trigger loud browser warnings and break secure trust chains.',
        remediation: 'Renew the SSL/TLS certificate immediately with your Certificate Authority (e.g., Let\'s Encrypt).',
      });
      remediationGuidance.push('Renew your expired TLS certificate immediately to restore browser trust.');
    } else if (tlsResult.isExpiringSoon) {
      findings.push({
        id: 'tls-validity',
        category: 'TLS Certificate',
        name: 'TLS Certificate Expiration',
        observed: `Expiring soon: ${tlsResult.daysRemaining} days remaining (Expires: ${tlsResult.validTo})`,
        status: 'Needs Review',
        importance: 'High',
        whyItMatters: 'Certificates expiring within 30 days risk sudden service outages if automated renewal fails.',
        remediation: 'Verify ACME / Let\'s Encrypt auto-renewal scripts or manually deploy a renewed certificate.',
      });
      remediationGuidance.push(`Renew your TLS certificate before it expires in ${tlsResult.daysRemaining} days.`);
    } else {
      findings.push({
        id: 'tls-validity',
        category: 'TLS Certificate',
        name: 'TLS Certificate Validity',
        observed: `${tlsResult.daysRemaining} days remaining (Valid until ${tlsResult.validTo})`,
        status: 'Passed',
        importance: 'High',
        whyItMatters: 'Certificates within their validity window establish cryptographic verification.',
        remediation: 'Ensure automated renewal pipelines continue monitoring expiration dates.',
      });
    }

    // Hostname Match
    completedChecks++;
    if (tlsResult.hostnameMatched) {
      findings.push({
        id: 'tls-hostname',
        category: 'TLS Certificate',
        name: 'TLS Hostname Verification',
        observed: `Hostname matches SAN/CN entries: ${tlsResult.subjectAltNames.slice(0, 3).join(', ')}`,
        status: 'Passed',
        importance: 'High',
        whyItMatters: 'Verifies the certificate was issued explicitly for the domain being accessed.',
        remediation: 'Keep Subject Alternative Names (SAN) updated when changing domains.',
      });
    } else {
      findings.push({
        id: 'tls-hostname',
        category: 'TLS Certificate',
        name: 'TLS Hostname Verification',
        observed: 'Hostname does not match certificate CN/SAN list',
        status: 'Warning',
        importance: 'Critical',
        whyItMatters: 'Browser displays "Certificate Name Mismatch" error, breaking connection trust.',
        remediation: 'Reissue certificate including this domain in the Subject Alternative Name (SAN) list.',
      });
      remediationGuidance.push('Reissue your TLS certificate with your exact domain name listed in the SAN (Subject Alternative Name).');
    }

    // Chain Trust
    completedChecks++;
    if (tlsResult.chainTrusted) {
      findings.push({
        id: 'tls-trust',
        category: 'TLS Certificate',
        name: 'Certificate Authority Chain Trust',
        observed: `Trusted root CA: ${tlsResult.issuer.raw}`,
        status: 'Passed',
        importance: 'High',
        whyItMatters: 'Ensures the certificate was signed by a recognized, audited public Certificate Authority.',
        remediation: 'Continue using established public CAs.',
      });
    } else {
      findings.push({
        id: 'tls-trust',
        category: 'TLS Certificate',
        name: 'Certificate Authority Chain Trust',
        observed: tlsResult.validationError || 'Untrusted certificate authority or self-signed',
        status: 'Warning',
        importance: 'High',
        whyItMatters: 'Self-signed or broken certificate chains trigger red security warnings for website visitors.',
        remediation: 'Ensure the complete intermediate CA bundle is installed alongside your leaf certificate.',
      });
      remediationGuidance.push('Install complete intermediate CA certificates or replace self-signed certificates with a public trusted CA.');
    }
  } else {
    unverifiedChecks += 3;
    findings.push({
      id: 'tls-unverified',
      category: 'TLS Certificate',
      name: 'TLS Certificate Inspection',
      observed: tlsResult.detailsMessage,
      status: 'Unable to Verify',
      importance: 'Medium',
      whyItMatters: 'Could not establish a direct TLS connection on port 443.',
      remediation: 'Verify whether the server listener is running and firewall rules allow incoming port 443 traffic.',
    });
  }

  // ── 4. Evaluate HTTP Security Headers ───────────────────────────────────────
  for (const hf of headerResult.headerFindings) {
    completedChecks++;
    let mappedStatus: DetailedFinding['status'] = 'Passed';
    if (hf.status === 'Missing') {
      mappedStatus = hf.importance === 'Informational' ? 'Needs Review' : 'Needs Review';
      if (hf.importance === 'High') {
        remediationGuidance.push(hf.recommendation);
      }
    } else if (hf.status === 'Needs Review') {
      mappedStatus = 'Needs Review';
      remediationGuidance.push(hf.recommendation);
    }

    findings.push({
      id: `header-${hf.header.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      category: 'Security Headers',
      name: hf.header,
      observed: hf.value ? `${hf.value}` : 'Not Present',
      status: mappedStatus,
      importance: hf.importance,
      whyItMatters: hf.explanation,
      remediation: hf.recommendation,
    });
  }

  // ── 5. Server Header Disclosure ─────────────────────────────────────────────
  completedChecks++;
  if (headerResult.serverInfo.leaksVersion) {
    findings.push({
      id: 'server-version-leak',
      category: 'Server Configuration',
      name: 'Server Header Version Disclosure',
      observed: [headerResult.serverInfo.serverHeader, headerResult.serverInfo.poweredBy].filter(Boolean).join(' / '),
      status: 'Needs Review',
      importance: 'Low',
      whyItMatters: 'Exposing explicit version numbers (e.g. Apache/2.4.41) assists attackers in fingerprinting known CVEs.',
      remediation: 'Configure server tokens to minimal/off (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).',
    });
    remediationGuidance.push('Minimize Server and X-Powered-By header version numbers in your web server configuration.');
  } else {
    findings.push({
      id: 'server-version-leak',
      category: 'Server Configuration',
      name: 'Server Header Version Disclosure',
      observed: headerResult.serverInfo.serverHeader ? 'Generic identifier' : 'No server header leaked',
      status: 'Passed',
      importance: 'Low',
      whyItMatters: 'Prevents automated vulnerability scanners from pinpointing obsolete server builds.',
      remediation: 'Maintain minimal server signature posture.',
    });
  }

  // ── 6. Compute Documented Score (0 - 100) ───────────────────────────────────
  let httpsPoints = 0;
  if (headerResult.httpsAvailable) httpsPoints = 25;

  let tlsPoints = 0;
  if (tlsResult.available) {
    if (tlsResult.isExpired) {
      tlsPoints = 0;
    } else if (tlsResult.isExpiringSoon) {
      tlsPoints = 18;
    } else if (!tlsResult.hostnameMatched) {
      tlsPoints = 5;
    } else if (!tlsResult.chainTrusted) {
      tlsPoints = 12;
    } else {
      tlsPoints = 25;
    }
  }

  let redirectPoints = 0;
  if (headerResult.httpToHttpsRedirect) redirectPoints = 10;

  // Header points
  const hstsFinding = headerResult.headerFindings.find((h) => h.header.includes('HSTS'));
  let hstsPoints = 0;
  if (hstsFinding?.status === 'Present') hstsPoints = 15;
  else if (hstsFinding?.status === 'Needs Review') hstsPoints = 8;

  const cspFinding = headerResult.headerFindings.find((h) => h.header.includes('CSP'));
  let cspPoints = 0;
  if (cspFinding?.status === 'Present') cspPoints = 10;
  else if (cspFinding?.status === 'Needs Review') cspPoints = 6;

  const xctoFinding = headerResult.headerFindings.find((h) => h.header.includes('X-Content-Type-Options'));
  let xctoPoints = 0;
  if (xctoFinding?.status === 'Present') xctoPoints = 5;

  const framingFinding = headerResult.headerFindings.find((h) => h.header.includes('Frame'));
  let framingPoints = 0;
  if (framingFinding?.status === 'Present') framingPoints = 5;

  const rpFinding = headerResult.headerFindings.find((h) => h.header.includes('Referrer'));
  let referrerPoints = 0;
  if (rpFinding?.status === 'Present') referrerPoints = 3;
  else if (rpFinding?.status === 'Needs Review') referrerPoints = 1;

  const ppFinding = headerResult.headerFindings.find((h) => h.header.includes('Permissions'));
  let permissionsPoints = 0;
  if (ppFinding?.status === 'Present') permissionsPoints = 2;

  const totalRaw =
    httpsPoints +
    tlsPoints +
    redirectPoints +
    hstsPoints +
    cspPoints +
    xctoPoints +
    framingPoints +
    referrerPoints +
    permissionsPoints;

  const finalScore = Math.max(0, Math.min(100, Math.round(totalRaw)));

  let scoreLabel: SecurityScoreBreakdown['label'] = 'Grade F';
  if (finalScore >= 85) scoreLabel = 'Grade A';
  else if (finalScore >= 70) scoreLabel = 'Grade B';
  else if (finalScore >= 55) scoreLabel = 'Grade C';
  else if (finalScore >= 40) scoreLabel = 'Grade D';

  // Count findings by status
  const passedCount = findings.filter((f) => f.status === 'Passed').length;
  const reviewCount = findings.filter((f) => f.status === 'Needs Review').length;
  const warningCount = findings.filter((f) => f.status === 'Warning').length;

  // Overview Cards Colors
  const httpsCardStatus: 'green' | 'amber' | 'red' | 'gray' =
    !headerResult.httpsAvailable
      ? 'red'
      : !headerResult.httpToHttpsRedirect
      ? 'amber'
      : 'green';

  const tlsCardStatus: 'green' | 'amber' | 'red' | 'gray' =
    !tlsResult.available
      ? 'gray'
      : tlsResult.isExpired || !tlsResult.hostnameMatched
      ? 'red'
      : tlsResult.isExpiringSoon || !tlsResult.chainTrusted
      ? 'amber'
      : 'green';

  const headerCardStatus: 'green' | 'amber' | 'red' | 'gray' =
    hstsPoints >= 15 && cspPoints >= 8
      ? 'green'
      : hstsPoints > 0 || cspPoints > 0
      ? 'amber'
      : 'red';

  const configCardStatus: 'green' | 'amber' | 'red' | 'gray' =
    warningCount === 0 && reviewCount <= 2 ? 'green' : reviewCount <= 4 ? 'amber' : 'red';

  return {
    target: {
      originalUrl: target.originalUrl,
      normalizedUrl: target.normalizedUrl,
      hostname: target.hostname,
      ipAddress: target.primaryIp,
      finalUrl: headerResult.finalUrl,
    },
    scanTimestamp: new Date().toISOString(),
    scanStatus: unverifiedChecks > 0 && completedChecks > 0 ? 'Partial' : 'Completed',
    summary: {
      completedChecks,
      unverifiedChecks,
      totalFindings: findings.length,
      passedCount,
      reviewCount,
      warningCount,
    },
    scoreBreakdown: {
      score: finalScore,
      label: scoreLabel,
      disclaimer: 'Basic Configuration Score — Not a Measure of Overall Website Security.',
      formula: {
        httpsPoints,
        tlsPoints,
        redirectPoints,
        hstsPoints,
        cspPoints,
        xctoPoints,
        framingPoints,
        referrerPoints,
        permissionsPoints,
        totalPossible: 100,
      },
    },
    overviewCards: {
      httpsSecurity: {
        status: httpsCardStatus,
        title: headerResult.httpsStatus,
        subtitle: headerResult.httpToHttpsRedirect
          ? 'Port 80 redirects to HTTPS'
          : 'No automatic HTTP redirect',
      },
      tlsCertificate: {
        status: tlsCardStatus,
        title: tlsResult.status,
        subtitle: tlsResult.available
          ? `${tlsResult.daysRemaining} days remaining · ${tlsResult.issuer.raw}`
          : 'TLS port unreachable',
      },
      securityHeaders: {
        status: headerCardStatus,
        title: `${headerResult.headerFindings.filter((h) => h.status === 'Present').length} of ${headerResult.headerFindings.length} Present`,
        subtitle: hstsPoints > 0 ? 'HSTS configured' : 'HSTS missing',
      },
      configuration: {
        status: configCardStatus,
        title: warningCount > 0 ? `${warningCount} Critical Issues` : 'Standard Configuration',
        subtitle: reviewCount > 0 ? `${reviewCount} areas to review` : 'All baseline checks passed',
      },
    },
    tlsDetails: tlsResult,
    headerDetails: headerResult,
    findings,
    remediationGuidance: Array.from(new Set(remediationGuidance)),
  };
};
