import http from 'http';
import https from 'https';
import zlib from 'zlib';
import { TLSSocket } from 'tls';
import { resolveAllowedAddress, TargetRejectedError } from './targetGuard';

/**
 * Bounded, SSRF-safe HTTP client shared by all scanner checks.
 *
 *  - connects only to the DNS-validated IP (pinned lookup, re-validated per hop)
 *  - manual redirects with a hop limit; every hop is validated again
 *  - only GET / HEAD / OPTIONS / TRACE, never a request body
 *  - only a fixed set of request headers can be set by checks (no user headers)
 *  - per-request timeout, response size cap, per-scan concurrency and request budget
 *  - cooperative cancellation through the scan's AbortSignal
 */

export type SafeMethod = 'GET' | 'HEAD' | 'OPTIONS' | 'TRACE';

const ALLOWED_REQUEST_HEADERS = new Set([
  'accept',
  'origin',
  'access-control-request-method',
  'access-control-request-headers',
  'range',
]);

export const USER_AGENT = 'RAKSHAK-VulnScanner/1.0 (authorized security assessment)';

export class ProbeError extends Error {
  constructor(readonly code: 'TIMEOUT' | 'CANCELLED' | 'BLOCKED' | 'NETWORK' | 'BUDGET' | 'REDIRECT_LIMIT', message: string) {
    super(message);
    this.name = 'ProbeError';
  }
}

export interface TlsDetails {
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipher: string | null;
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
}

export interface HttpResult {
  requestedUrl: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  bytes: number;
  truncated: boolean;
  redirects: RedirectHop[];
  timingMs: number;
  tls: TlsDetails | null;
}

export interface RequestOptions {
  method?: SafeMethod;
  headers?: Record<string, string>;
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  readBody?: boolean;
}

/** Simple FIFO semaphore limiting concurrent requests per scan. */
class Semaphore {
  private queue: Array<() => void> = [];
  private active = 0;
  constructor(private readonly limit: number) {}
  async acquire(): Promise<() => void> {
    if (this.active >= this.limit) await new Promise<void>((resolve) => this.queue.push(resolve));
    this.active += 1;
    return () => {
      this.active -= 1;
      this.queue.shift()?.();
    };
  }
}

export class ScanHttpClient {
  requestCount = 0;
  private readonly semaphore: Semaphore;

  constructor(
    private readonly signal: AbortSignal,
    private readonly maxRequests: number,
    concurrency = 4
  ) {
    this.semaphore = new Semaphore(concurrency);
  }

  async request(target: string, options: RequestOptions = {}): Promise<HttpResult> {
    const method = options.method ?? 'GET';
    const maxRedirects = options.maxRedirects ?? 0;
    const redirects: RedirectHop[] = [];
    const started = Date.now();
    let current = new URL(target);

    for (let hop = 0; ; hop += 1) {
      const result = await this.single(current, method, options);
      const location = result.headers['location'];
      const isRedirect = result.status >= 300 && result.status < 400 && location;
      if (!isRedirect || hop >= maxRedirects) {
        return { ...result, requestedUrl: target, redirects, timingMs: Date.now() - started };
      }
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        return { ...result, requestedUrl: target, redirects, timingMs: Date.now() - started };
      }
      redirects.push({ url: current.href, status: result.status, location: next.href });
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return { ...result, requestedUrl: target, redirects, timingMs: Date.now() - started };
      }
      if (redirects.some((r) => r.url === next.href)) {
        throw new ProbeError('REDIRECT_LIMIT', 'Redirect loop detected.');
      }
      current = next;
    }
  }

  private async single(url: URL, method: SafeMethod, options: RequestOptions): Promise<Omit<HttpResult, 'requestedUrl' | 'redirects' | 'timingMs'>> {
    if (this.signal.aborted) throw new ProbeError('CANCELLED', 'Scan cancelled.');
    if (this.requestCount >= this.maxRequests) throw new ProbeError('BUDGET', 'Request budget for this scan exhausted.');
    this.requestCount += 1;

    const release = await this.semaphore.acquire();
    try {
      const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
      let pinned: { address: string; family: 4 | 6 };
      try {
        pinned = await resolveAllowedAddress(url.hostname, port);
      } catch (err) {
        if (err instanceof TargetRejectedError) throw new ProbeError('BLOCKED', err.message);
        throw err;
      }
      return await this.send(url, port, pinned, method, options);
    } finally {
      release();
    }
  }

  private send(
    url: URL,
    port: number,
    pinned: { address: string; family: 4 | 6 },
    method: SafeMethod,
    options: RequestOptions
  ): Promise<Omit<HttpResult, 'requestedUrl' | 'redirects' | 'timingMs'>> {
    const maxBytes = options.maxBytes ?? 256 * 1024;
    const timeoutMs = options.timeoutMs ?? 8000;
    const readBody = options.readBody ?? (method === 'GET' || method === 'TRACE');

    const headers: Record<string, string> = {
      'User-Agent': USER_AGENT,
      Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      Connection: 'close',
    };
    for (const [name, value] of Object.entries(options.headers ?? {})) {
      if (ALLOWED_REQUEST_HEADERS.has(name.toLowerCase())) headers[name] = String(value).slice(0, 512);
    }

    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.signal.removeEventListener('abort', onAbort);
        fn();
      };

      const req = lib.request(
        {
          protocol: url.protocol,
          hostname: url.hostname.replace(/^\[|\]$/g, ''),
          port,
          path: `${url.pathname}${url.search}`,
          method,
          headers,
          agent: false,
          // Pin the connection to the validated address. Node may ask for all
          // addresses (opts.all) or a single one; both forms are supported.
          lookup: (_host: string, opts: any, cb: any) => {
            if (opts && opts.all) cb(null, [{ address: pinned.address, family: pinned.family }]);
            else cb(null, pinned.address, pinned.family);
          },
          ...(isHttps ? { rejectUnauthorized: false, servername: url.hostname.replace(/^\[|\]$/g, '') } : {}),
        },
        (res) => {
          const socket = res.socket as TLSSocket;
          const tls: TlsDetails | null = isHttps
            ? {
                authorized: Boolean(socket?.authorized),
                authorizationError: socket?.authorizationError ? String(socket.authorizationError) : null,
                protocol: typeof socket?.getProtocol === 'function' ? socket.getProtocol() : null,
                cipher: typeof socket?.getCipher === 'function' ? socket.getCipher()?.name ?? null : null,
              }
            : null;

          const responseHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (key === 'set-cookie') continue;
            responseHeaders[key] = Array.isArray(value) ? value.join(', ') : String(value ?? '');
          }
          const setCookies = res.headers['set-cookie'] ?? [];
          const base = { url: url.href, status: res.statusCode ?? 0, headers: responseHeaders, setCookies, tls };

          if (!readBody || method === 'HEAD') {
            res.resume();
            finish(() => resolve({ ...base, body: '', bytes: 0, truncated: false }));
            req.destroy();
            return;
          }

          const encoding = String(res.headers['content-encoding'] || '').toLowerCase();
          let stream: NodeJS.ReadableStream = res;
          if (encoding.includes('gzip')) stream = res.pipe(zlib.createGunzip());
          else if (encoding.includes('deflate')) stream = res.pipe(zlib.createInflate());
          else if (encoding.includes('br')) stream = res.pipe(zlib.createBrotliDecompress());

          const chunks: Buffer[] = [];
          let bytes = 0;
          let truncated = false;
          const done = () =>
            finish(() => resolve({ ...base, body: Buffer.concat(chunks).toString('utf8'), bytes, truncated }));

          stream.on('data', (chunk: Buffer) => {
            if (truncated) return;
            const remaining = maxBytes - bytes;
            if (chunk.length > remaining) {
              chunks.push(chunk.subarray(0, Math.max(0, remaining)));
              bytes = maxBytes;
              truncated = true;
              done();
              req.destroy();
              return;
            }
            chunks.push(chunk);
            bytes += chunk.length;
          });
          stream.on('end', done);
          stream.on('error', () => done()); // malformed compression: keep what was read
          res.on('aborted', done);
        }
      );

      const timer = setTimeout(() => {
        finish(() => reject(new ProbeError('TIMEOUT', `No response within ${Math.round(timeoutMs / 1000)}s.`)));
        req.destroy();
      }, timeoutMs);

      const onAbort = () => {
        finish(() => reject(new ProbeError('CANCELLED', 'Scan cancelled.')));
        req.destroy();
      };
      this.signal.addEventListener('abort', onAbort, { once: true });

      req.on('error', (err: any) => {
        finish(() => reject(new ProbeError('NETWORK', `${err?.code || 'NETWORK_ERROR'}: ${String(err?.message || '').slice(0, 160)}`)));
      });
      req.end();
    });
  }
}

/** Case-insensitive header lookup helper. */
export const header = (result: HttpResult, name: string): string | undefined => result.headers[name.toLowerCase()];

export const isHtml = (result: HttpResult) => /text\/html|application\/xhtml/i.test(header(result, 'content-type') || '');
