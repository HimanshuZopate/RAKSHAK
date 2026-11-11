import tls from 'tls';
import { ValidatedTarget } from './ssrfProtection';

export interface TlsScanResult {
  available: boolean;
  status: 'Validity Dates OK' | 'Expiring Soon' | 'Expired' | 'Certificate Validation Failed' | 'Unable to Verify';
  issuer: {
    commonName?: string;
    organization?: string;
    country?: string;
    raw: string;
  };
  subject: {
    commonName?: string;
    organization?: string;
    raw: string;
  };
  subjectAltNames: string[];
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  isExpired: boolean;
  isExpiringSoon: boolean;
  hostnameMatched: boolean;
  chainTrusted: boolean;
  validationError?: string | null;
  protocol?: string | null;
  cipher?: string | null;
  fingerprint?: string | null;
  serialNumber?: string | null;
  detailsMessage: string;
}

/**
 * Check if a hostname matches a Subject Alternative Name (SAN) pattern
 * Handles standard wildcards e.g. *.example.com matches sub.example.com
 */
const matchesDomainPattern = (hostname: string, pattern: string): boolean => {
  const h = hostname.toLowerCase();
  const p = pattern.toLowerCase().trim();

  if (p.startsWith('dns:')) {
    return matchesDomainPattern(h, p.substring(4));
  }

  if (h === p) return true;

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
export const inspectTlsCertificate = (
  target: ValidatedTarget,
  timeoutMs: number = 6000
): Promise<TlsScanResult> => {
  return new Promise((resolve) => {
    const port = target.port === 80 ? 443 : target.port;

    const socketOptions: tls.ConnectionOptions = {
      host: target.primaryIp, // Connected directly to SSRF-validated IP
      port,
      servername: target.hostname, // Server Name Indication (SNI)
      rejectUnauthorized: false, // We inspect cert manually to report self-signed/expired certs accurately!
      timeout: timeoutMs,
    };

    let socket: tls.TLSSocket;

    try {
      socket = tls.connect(socketOptions, () => {
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

          let daysRemaining: number | null = null;
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
          const subjectCN = peerCert.subject?.CN || '';
          const candidateNames = [...sans];
          if (subjectCN && !candidateNames.includes(subjectCN)) {
            candidateNames.push(subjectCN);
          }

          const hostnameMatched = candidateNames.some((pattern) =>
            matchesDomainPattern(target.hostname, pattern)
          );

          // Determine status
          let status: TlsScanResult['status'] = 'Validity Dates OK';
          let detailsMessage = `Certificate is valid and active for ${daysRemaining} more days.`;

          if (isExpired) {
            status = 'Expired';
            detailsMessage = `Certificate expired on ${validToDate?.toUTCString()}.`;
          } else if (isExpiringSoon) {
            status = 'Expiring Soon';
            detailsMessage = `Certificate expires within 30 days (${daysRemaining} days remaining). Renewal recommended.`;
          } else if (!hostnameMatched) {
            status = 'Certificate Validation Failed';
            detailsMessage = `Hostname mismatch: certificate is issued for ${candidateNames.slice(0, 3).join(', ')} but target is ${target.hostname}.`;
          } else if (!authorized && authorizationError) {
            status = 'Certificate Validation Failed';
            detailsMessage = `Certificate trust issue: ${authorizationError}.`;
          }

          return resolve({
            available: true,
            status,
            issuer: {
              commonName: peerCert.issuer?.CN,
              organization: peerCert.issuer?.O,
              country: peerCert.issuer?.C,
              raw: peerCert.issuer?.O || peerCert.issuer?.CN || 'Unknown Issuer',
            },
            subject: {
              commonName: peerCert.subject?.CN,
              organization: peerCert.subject?.O,
              raw: peerCert.subject?.CN || peerCert.subject?.O || target.hostname,
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
        } catch (err: any) {
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

      socket.on('error', (err: any) => {
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
    } catch (err: any) {
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
