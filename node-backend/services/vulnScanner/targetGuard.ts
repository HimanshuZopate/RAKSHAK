import dns from 'dns';
import net from 'net';
import { isPrivateOrReservedIP } from '../websiteScanner/ssrfProtection';

/**
 * Target validation & SSRF protection for the vulnerability scanner.
 *
 * Every outbound request (including each redirect hop) goes through
 * resolveAllowedAddress(), which resolves DNS and rejects any private,
 * loopback, link-local, metadata, multicast or reserved address. The HTTP
 * client then connects to that exact validated IP, so a DNS rebinding answer
 * returned after validation can never be used.
 */

export class TargetRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TargetRejectedError';
  }
}

export interface ScanTarget {
  url: URL;
  origin: string;
  hostname: string;
  port: number;
  isLab: boolean;
}

const ALLOWED_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888]);
const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home', '.corp', '.intranet'];
const METADATA_HOSTS = new Set(['metadata.google.internal', 'metadata', 'instance-data', 'instance-data.ec2.internal']);

/**
 * Lab allowlist for controlled local demonstrations, e.g.
 *   VULN_SCANNER_LAB_TARGETS=127.0.0.1:4455,127.0.0.1:4456
 * Only exact loopback host:port pairs are honoured; nothing else is relaxed.
 */
const labTargets = (): Set<string> =>
  new Set(
    String(process.env.VULN_SCANNER_LAB_TARGETS || '')
      .split(',')
      .map((v) => v.trim().toLowerCase())
      .filter((v) => /^(127\.0\.0\.1|localhost):\d{2,5}$/.test(v))
  );

export const isLabTarget = (hostname: string, port: number) => labTargets().has(`${hostname.toLowerCase()}:${port}`);

/** IPv6 forms that embed IPv4 or are otherwise non-global, beyond the shared classifier. */
const isBlockedIPv6Extra = (ip: string): boolean => {
  const v = ip.toLowerCase();
  if (v.startsWith('64:ff9b:')) return true; // NAT64
  if (v.startsWith('2002:')) return true; // 6to4
  if (v.startsWith('2001:0:') || v.startsWith('2001:0000:')) return true; // Teredo
  if (v.startsWith('100::')) return true; // discard prefix
  // ::/96 IPv4-compatible and ::ffff:0:0/96 IPv4-mapped, in dotted (::ffff:127.0.0.1)
  // or hex (::ffff:7f00:1) form. No globally routable unicast address starts with "::".
  if (v.startsWith('::')) return true;
  return false;
};

export const isBlockedAddress = (ip: string): boolean => {
  if (!net.isIP(ip)) return true;
  if (net.isIPv4(ip) && /^192\.88\.99\./.test(ip)) return true; // 6to4 relay anycast
  if (net.isIPv6(ip) && isBlockedIPv6Extra(ip)) return true;
  return isPrivateOrReservedIP(ip);
};

/** Parses and normalises a user-supplied target URL (no network access). */
export const parseScanTarget = (input: unknown): ScanTarget => {
  if (typeof input !== 'string' || !input.trim()) throw new TargetRejectedError('A target URL is required.');
  const raw = input.trim();
  if (raw.length > 2048) throw new TargetRejectedError('The URL is longer than 2048 characters.');
  if (/[\u0000-\u001f\s]/.test(raw)) throw new TargetRejectedError('The URL contains whitespace or control characters.');

  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new TargetRejectedError('The URL is not valid.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TargetRejectedError(`Unsupported protocol "${url.protocol}". Only HTTP and HTTPS can be scanned.`);
  }
  if (url.username || url.password) throw new TargetRejectedError('URLs with embedded credentials are not allowed.');

  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) throw new TargetRejectedError('The URL has no hostname.');
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  const isLab = isLabTarget(hostname, port);
  url.hash = '';

  if (!isLab) {
    if (!ALLOWED_PORTS.has(port)) {
      throw new TargetRejectedError(`Port ${port} is not allowed. Allowed ports: ${[...ALLOWED_PORTS].join(', ')}.`);
    }
    if (hostname === 'localhost' || BLOCKED_HOST_SUFFIXES.some((s) => hostname.endsWith(s)) || METADATA_HOSTS.has(hostname)) {
      throw new TargetRejectedError('Local, internal and cloud-metadata hostnames cannot be scanned.');
    }
    if (!net.isIP(hostname) && !hostname.includes('.')) {
      throw new TargetRejectedError('Single-label hostnames (internal names) cannot be scanned.');
    }
    if (net.isIP(hostname) && isBlockedAddress(hostname)) {
      throw new TargetRejectedError('Private, loopback, link-local, metadata and reserved IP addresses cannot be scanned.');
    }
  }

  return { url, origin: url.origin, hostname, port, isLab };
};

/**
 * Resolves a hostname and returns one validated address to connect to.
 * Called for every request, so DNS changes during a scan are re-checked.
 */
export const resolveAllowedAddress = async (
  hostname: string,
  port: number
): Promise<{ address: string; family: 4 | 6 }> => {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (isLabTarget(host, port)) {
    return { address: '127.0.0.1', family: 4 };
  }
  if (!ALLOWED_PORTS.has(port)) throw new TargetRejectedError(`Port ${port} is not allowed.`);

  if (net.isIP(host)) {
    if (isBlockedAddress(host)) throw new TargetRejectedError('Destination address is not publicly routable.');
    return { address: host, family: net.isIPv6(host) ? 6 : 4 };
  }

  let records: dns.LookupAddress[];
  try {
    records = await dns.promises.lookup(host, { all: true, verbatim: true });
  } catch (err: any) {
    throw new TargetRejectedError(`DNS lookup failed for ${host} (${err?.code || 'unknown error'}).`);
  }
  if (!records.length) throw new TargetRejectedError(`No DNS records found for ${host}.`);

  // DNS64 resolvers synthesise NAT64 addresses (64:ff9b::/96) that wrap the real IPv4.
  // Validate the embedded IPv4: private → reject; public → drop the synthetic record
  // (we never connect to it) and use the genuine records.
  const usable: dns.LookupAddress[] = [];
  for (const record of records) {
    const embedded = record.family === 6 ? nat64EmbeddedIPv4(record.address) : null;
    if (embedded) {
      if (isBlockedAddress(embedded)) throw new TargetRejectedError(`${host} resolves to a private or reserved address.`);
      continue;
    }
    // Reject if ANY genuine record is internal: a mixed answer is a classic rebinding setup.
    if (isBlockedAddress(record.address)) throw new TargetRejectedError(`${host} resolves to a private or reserved address.`);
    usable.push(record);
  }
  if (!usable.length) throw new TargetRejectedError(`${host} has no directly reachable public address.`);
  const chosen = usable.find((r) => r.family === 4) || usable[0];
  return { address: chosen.address, family: chosen.family === 6 ? 6 : 4 };
};

/** Returns the IPv4 embedded in a NAT64 well-known-prefix address (64:ff9b::/96), else null. */
export const nat64EmbeddedIPv4 = (ip: string): string | null => {
  const v = ip.toLowerCase();
  if (!v.startsWith('64:ff9b::')) return null;
  const tail = v.slice('64:ff9b::'.length);
  if (net.isIPv4(tail)) return tail; // 64:ff9b::1.2.3.4
  const parts = tail.split(':');
  if (parts.length !== 2 || !parts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) return null;
  const [hi, lo] = parts.map((p) => parseInt(p, 16));
  return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
};
