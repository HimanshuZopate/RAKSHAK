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
exports.isHtml = exports.header = exports.ScanHttpClient = exports.ProbeError = exports.USER_AGENT = void 0;
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const zlib_1 = __importDefault(require("zlib"));
const targetGuard_1 = require("./targetGuard");
const ALLOWED_REQUEST_HEADERS = new Set([
    'accept',
    'origin',
    'access-control-request-method',
    'access-control-request-headers',
    'range',
]);
exports.USER_AGENT = 'RAKSHAK-VulnScanner/1.0 (authorized security assessment)';
class ProbeError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = 'ProbeError';
    }
}
exports.ProbeError = ProbeError;
/** Simple FIFO semaphore limiting concurrent requests per scan. */
class Semaphore {
    constructor(limit) {
        this.limit = limit;
        this.queue = [];
        this.active = 0;
    }
    acquire() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.active >= this.limit)
                yield new Promise((resolve) => this.queue.push(resolve));
            this.active += 1;
            return () => {
                var _a;
                this.active -= 1;
                (_a = this.queue.shift()) === null || _a === void 0 ? void 0 : _a();
            };
        });
    }
}
class ScanHttpClient {
    constructor(signal, maxRequests, concurrency = 4) {
        this.signal = signal;
        this.maxRequests = maxRequests;
        this.requestCount = 0;
        this.semaphore = new Semaphore(concurrency);
    }
    request(target, options = {}) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            const method = (_a = options.method) !== null && _a !== void 0 ? _a : 'GET';
            const maxRedirects = (_b = options.maxRedirects) !== null && _b !== void 0 ? _b : 0;
            const redirects = [];
            const started = Date.now();
            let current = new URL(target);
            for (let hop = 0;; hop += 1) {
                const result = yield this.single(current, method, options);
                const location = result.headers['location'];
                const isRedirect = result.status >= 300 && result.status < 400 && location;
                if (!isRedirect || hop >= maxRedirects) {
                    return Object.assign(Object.assign({}, result), { requestedUrl: target, redirects, timingMs: Date.now() - started });
                }
                let next;
                try {
                    next = new URL(location, current);
                }
                catch (_c) {
                    return Object.assign(Object.assign({}, result), { requestedUrl: target, redirects, timingMs: Date.now() - started });
                }
                redirects.push({ url: current.href, status: result.status, location: next.href });
                if (next.protocol !== 'http:' && next.protocol !== 'https:') {
                    return Object.assign(Object.assign({}, result), { requestedUrl: target, redirects, timingMs: Date.now() - started });
                }
                if (redirects.some((r) => r.url === next.href)) {
                    throw new ProbeError('REDIRECT_LIMIT', 'Redirect loop detected.');
                }
                current = next;
            }
        });
    }
    single(url, method, options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.signal.aborted)
                throw new ProbeError('CANCELLED', 'Scan cancelled.');
            if (this.requestCount >= this.maxRequests)
                throw new ProbeError('BUDGET', 'Request budget for this scan exhausted.');
            this.requestCount += 1;
            const release = yield this.semaphore.acquire();
            try {
                const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
                let pinned;
                try {
                    pinned = yield (0, targetGuard_1.resolveAllowedAddress)(url.hostname, port);
                }
                catch (err) {
                    if (err instanceof targetGuard_1.TargetRejectedError)
                        throw new ProbeError('BLOCKED', err.message);
                    throw err;
                }
                return yield this.send(url, port, pinned, method, options);
            }
            finally {
                release();
            }
        });
    }
    send(url, port, pinned, method, options) {
        var _a, _b, _c, _d;
        const maxBytes = (_a = options.maxBytes) !== null && _a !== void 0 ? _a : 256 * 1024;
        const timeoutMs = (_b = options.timeoutMs) !== null && _b !== void 0 ? _b : 8000;
        const readBody = (_c = options.readBody) !== null && _c !== void 0 ? _c : (method === 'GET' || method === 'TRACE');
        const headers = {
            'User-Agent': exports.USER_AGENT,
            Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            Connection: 'close',
        };
        for (const [name, value] of Object.entries((_d = options.headers) !== null && _d !== void 0 ? _d : {})) {
            if (ALLOWED_REQUEST_HEADERS.has(name.toLowerCase()))
                headers[name] = String(value).slice(0, 512);
        }
        const isHttps = url.protocol === 'https:';
        const lib = isHttps ? https_1.default : http_1.default;
        return new Promise((resolve, reject) => {
            let settled = false;
            const finish = (fn) => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timer);
                this.signal.removeEventListener('abort', onAbort);
                fn();
            };
            const req = lib.request(Object.assign({ protocol: url.protocol, hostname: url.hostname.replace(/^\[|\]$/g, ''), port, path: `${url.pathname}${url.search}`, method,
                headers, agent: false, 
                // Pin the connection to the validated address. Node may ask for all
                // addresses (opts.all) or a single one; both forms are supported.
                lookup: (_host, opts, cb) => {
                    if (opts && opts.all)
                        cb(null, [{ address: pinned.address, family: pinned.family }]);
                    else
                        cb(null, pinned.address, pinned.family);
                } }, (isHttps ? { rejectUnauthorized: false, servername: url.hostname.replace(/^\[|\]$/g, '') } : {})), (res) => {
                var _a, _b, _c, _d;
                const socket = res.socket;
                const tls = isHttps
                    ? {
                        authorized: Boolean(socket === null || socket === void 0 ? void 0 : socket.authorized),
                        authorizationError: (socket === null || socket === void 0 ? void 0 : socket.authorizationError) ? String(socket.authorizationError) : null,
                        protocol: typeof (socket === null || socket === void 0 ? void 0 : socket.getProtocol) === 'function' ? socket.getProtocol() : null,
                        cipher: typeof (socket === null || socket === void 0 ? void 0 : socket.getCipher) === 'function' ? (_b = (_a = socket.getCipher()) === null || _a === void 0 ? void 0 : _a.name) !== null && _b !== void 0 ? _b : null : null,
                    }
                    : null;
                const responseHeaders = {};
                for (const [key, value] of Object.entries(res.headers)) {
                    if (key === 'set-cookie')
                        continue;
                    responseHeaders[key] = Array.isArray(value) ? value.join(', ') : String(value !== null && value !== void 0 ? value : '');
                }
                const setCookies = (_c = res.headers['set-cookie']) !== null && _c !== void 0 ? _c : [];
                const base = { url: url.href, status: (_d = res.statusCode) !== null && _d !== void 0 ? _d : 0, headers: responseHeaders, setCookies, tls };
                if (!readBody || method === 'HEAD') {
                    res.resume();
                    finish(() => resolve(Object.assign(Object.assign({}, base), { body: '', bytes: 0, truncated: false })));
                    req.destroy();
                    return;
                }
                const encoding = String(res.headers['content-encoding'] || '').toLowerCase();
                let stream = res;
                if (encoding.includes('gzip'))
                    stream = res.pipe(zlib_1.default.createGunzip());
                else if (encoding.includes('deflate'))
                    stream = res.pipe(zlib_1.default.createInflate());
                else if (encoding.includes('br'))
                    stream = res.pipe(zlib_1.default.createBrotliDecompress());
                const chunks = [];
                let bytes = 0;
                let truncated = false;
                const done = () => finish(() => resolve(Object.assign(Object.assign({}, base), { body: Buffer.concat(chunks).toString('utf8'), bytes, truncated })));
                stream.on('data', (chunk) => {
                    if (truncated)
                        return;
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
            });
            const timer = setTimeout(() => {
                finish(() => reject(new ProbeError('TIMEOUT', `No response within ${Math.round(timeoutMs / 1000)}s.`)));
                req.destroy();
            }, timeoutMs);
            const onAbort = () => {
                finish(() => reject(new ProbeError('CANCELLED', 'Scan cancelled.')));
                req.destroy();
            };
            this.signal.addEventListener('abort', onAbort, { once: true });
            req.on('error', (err) => {
                finish(() => reject(new ProbeError('NETWORK', `${(err === null || err === void 0 ? void 0 : err.code) || 'NETWORK_ERROR'}: ${String((err === null || err === void 0 ? void 0 : err.message) || '').slice(0, 160)}`)));
            });
            req.end();
        });
    }
}
exports.ScanHttpClient = ScanHttpClient;
/** Case-insensitive header lookup helper. */
const header = (result, name) => result.headers[name.toLowerCase()];
exports.header = header;
const isHtml = (result) => /text\/html|application\/xhtml/i.test((0, exports.header)(result, 'content-type') || '');
exports.isHtml = isHtml;
