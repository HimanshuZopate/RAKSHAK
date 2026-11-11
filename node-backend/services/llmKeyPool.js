"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LLMKeyPool = exports.classifyLLMError = exports.nextPacificMidnight = exports.COOLDOWN_POLICY = void 0;
const crypto_1 = require("crypto");
// ── Cooldown policy ─────────────────────────────────────────────────────────
exports.COOLDOWN_POLICY = {
    rateLimitDefaultMs: 60000,
    rateLimitMinMs: 5000,
    rateLimitMaxMs: 15 * 60000,
    backoffBaseMs: 5000,
    backoffMaxMs: 5 * 60000,
    quotaFallbackMs: 60 * 60000,
    modelUnavailableMs: 60 * 60000, // key cannot serve the configured model; re-check hourly
};
/** Gemini daily quotas reset at midnight Pacific time. Adds a 1 minute safety buffer. */
const nextPacificMidnight = (now) => {
    try {
        const parts = new Intl.DateTimeFormat('en-US', {
            timeZone: 'America/Los_Angeles',
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        }).formatToParts(new Date(now));
        const get = (type) => { var _a; return Number(((_a = parts.find((p) => p.type === type)) === null || _a === void 0 ? void 0 : _a.value) || 0); };
        const hour = get('hour') % 24;
        const elapsedMs = (hour * 3600 + get('minute') * 60 + get('second')) * 1000;
        return now + (24 * 3600 * 1000 - elapsedMs) + 60000;
    }
    catch (_a) {
        return now + exports.COOLDOWN_POLICY.quotaFallbackMs;
    }
};
exports.nextPacificMidnight = nextPacificMidnight;
/** Parses "12s", "1.5s" (google.protobuf.Duration JSON form). */
const parseDurationMs = (value) => {
    if (typeof value !== 'string')
        return null;
    const match = value.trim().match(/^(\d+(?:\.\d+)?)s$/);
    return match ? Math.round(parseFloat(match[1]) * 1000) : null;
};
/** Parses a Retry-After header (delta-seconds or HTTP-date). */
const parseRetryAfterHeader = (value, now) => {
    if (typeof value !== 'string' && typeof value !== 'number')
        return null;
    const raw = String(value).trim();
    if (/^\d+(?:\.\d+)?$/.test(raw))
        return Math.round(parseFloat(raw) * 1000);
    const date = Date.parse(raw);
    return Number.isNaN(date) ? null : Math.max(0, date - now);
};
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
/**
 * Inspects an axios-style error (or an internal Error with a code) and decides
 * what went wrong. Understands Google's google.rpc error details (QuotaFailure,
 * RetryInfo, ErrorInfo) and OpenAI-compatible error bodies (Groq, OpenAI).
 */
const classifyLLMError = (err, now = Date.now()) => {
    var _a, _b, _c;
    const result = (category, keyScoped, retryWithNextKey, httpStatus = null, retryAfterMs = null) => ({ category, keyScoped, retryWithNextKey, httpStatus, retryAfterMs });
    if ((err === null || err === void 0 ? void 0 : err.code) === 'AI_EMPTY_RESPONSE' || (err === null || err === void 0 ? void 0 : err.message) === 'AI_EMPTY_RESPONSE') {
        return result('empty_response', false, false);
    }
    const response = err === null || err === void 0 ? void 0 : err.response;
    if (!response) {
        const code = String((err === null || err === void 0 ? void 0 : err.code) || '');
        const message = String((err === null || err === void 0 ? void 0 : err.message) || '');
        if (code === 'ECONNABORTED' || code === 'ETIMEDOUT' || code === 'ERR_CANCELED' || /timeout/i.test(message)) {
            return result('timeout', true, true);
        }
        if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'EHOSTUNREACH'].includes(code)) {
            // Network-level failure affects every key of the provider equally.
            return result('network', false, false);
        }
        return result('unknown', true, true);
    }
    const status = Number(response.status) || 0;
    const body = response.data || {};
    const apiError = body.error || {};
    const message = String(apiError.message || body.message || '');
    const statusText = String(apiError.status || apiError.code || apiError.type || '');
    const details = Array.isArray(apiError.details) ? apiError.details : [];
    const detailOfType = (suffix) => details.find((d) => String((d === null || d === void 0 ? void 0 : d['@type']) || '').endsWith(suffix));
    const headerRetry = parseRetryAfterHeader((_a = response.headers) === null || _a === void 0 ? void 0 : _a['retry-after'], now);
    const rpcRetry = parseDurationMs((_b = detailOfType('RetryInfo')) === null || _b === void 0 ? void 0 : _b.retryDelay);
    const retryAfterMs = rpcRetry !== null && rpcRetry !== void 0 ? rpcRetry : headerRetry;
    if (status === 429 || /RESOURCE_EXHAUSTED/i.test(statusText)) {
        const violations = ((_c = detailOfType('QuotaFailure')) === null || _c === void 0 ? void 0 : _c.violations) || [];
        const quotaIds = violations.map((v) => `${(v === null || v === void 0 ? void 0 : v.quotaId) || ''} ${(v === null || v === void 0 ? void 0 : v.quotaMetric) || ''}`).join(' ');
        const isDaily = /per_?day|PerDay|daily/i.test(quotaIds) || /per day|daily/i.test(message);
        const zeroLimit = /limit:\s*0\b/i.test(message); // model not available on this tier at all
        const isQuota = /insufficient_quota|billing|exceeded your current quota/i.test(`${statusText} ${message}`);
        if (isDaily || zeroLimit || (isQuota && !rpcRetry && !headerRetry)) {
            return result('quota_exhausted', true, true, status, retryAfterMs);
        }
        return result('rate_limited', true, true, status, retryAfterMs);
    }
    if (status === 401 || /API_KEY_INVALID|invalid[_ ]api[_ ]key|API key not valid|API key expired/i.test(`${statusText} ${message} ${JSON.stringify(details)}`)) {
        return result('invalid_key', true, true, status);
    }
    if (status === 403 || /PERMISSION_DENIED/i.test(statusText)) {
        return result('permission_denied', true, true, status);
    }
    if (status === 404) {
        // Model availability can differ per project/key (e.g. Google retires models
        // "for new users" only), so this is tracked per key and the next key is tried.
        return result('model_not_found', true, true, status);
    }
    if (status === 400 || status === 413 || status === 422) {
        return result('bad_request', false, false, status);
    }
    if (status >= 500) {
        return result('server_error', true, true, status, retryAfterMs);
    }
    return result('unknown', true, true, status, retryAfterMs);
};
exports.classifyLLMError = classifyLLMError;
/**
 * A pool of API keys for one provider.
 */
class LLMKeyPool {
    constructor(provider, keys) {
        this.provider = provider;
        this.secrets = new Map();
        this.health = new Map();
        const unique = Array.from(new Set(keys.map((k) => (k || '').trim()).filter(Boolean)));
        unique.forEach((secret, index) => {
            const id = unique.length === 1 && provider !== 'gemini' ? `${provider}-key` : `${provider}-key-${index + 1}`;
            this.secrets.set(id, secret);
            this.health.set(id, {
                id,
                status: 'available',
                lastSuccessAt: null,
                lastFailureAt: null,
                lastErrorCategory: null,
                cooldownUntil: null,
                failureCount: 0,
            });
        });
    }
    get size() {
        return this.secrets.size;
    }
    /** Moves keys whose cooldown has expired back to "available". */
    refresh(h, now) {
        if (h.status === 'cooldown' && (h.cooldownUntil || 0) <= now) {
            h.status = 'available';
            h.cooldownUntil = null;
        }
    }
    eligibleIds(now = Date.now(), exclude = new Set()) {
        const ids = [];
        this.health.forEach((h) => {
            this.refresh(h, now);
            if (h.status === 'available' && !exclude.has(h.id))
                ids.push(h.id);
        });
        return ids;
    }
    /** Randomly selects an available key that has not been tried yet for this request. */
    pick(exclude, now = Date.now()) {
        const ids = this.eligibleIds(now, exclude);
        if (!ids.length)
            return null;
        const id = ids.length === 1 ? ids[0] : ids[(0, crypto_1.randomInt)(ids.length)];
        return { id, apiKey: this.secrets.get(id) };
    }
    reportSuccess(id, attemptStartedAt, now = Date.now()) {
        const h = this.health.get(id);
        if (!h)
            return;
        h.lastSuccessAt = now;
        // A concurrent request may have recorded a failure *after* this attempt
        // started (e.g. the per-minute quota ran out meanwhile). Keep that newer state.
        if (h.status === 'disabled' || (h.lastFailureAt !== null && h.lastFailureAt >= attemptStartedAt))
            return;
        h.status = 'available';
        h.cooldownUntil = null;
        h.failureCount = 0;
        h.lastErrorCategory = null;
    }
    reportFailure(id, error, attemptStartedAt, now = Date.now()) {
        var _a;
        const h = this.health.get(id);
        if (!h || !error.keyScoped)
            return h || null;
        // If a parallel request already penalised this key after our attempt began,
        // merge instead of counting the same incident twice.
        const alreadyRecorded = h.lastFailureAt !== null && h.lastFailureAt >= attemptStartedAt;
        h.lastFailureAt = now;
        h.lastErrorCategory = error.category;
        if (h.status === 'disabled')
            return h;
        if (error.category === 'invalid_key' || error.category === 'permission_denied') {
            h.status = 'disabled'; // stays disabled until the configuration is corrected (restart)
            h.cooldownUntil = null;
            return h;
        }
        if (!alreadyRecorded)
            h.failureCount += 1;
        let cooldownMs;
        switch (error.category) {
            case 'quota_exhausted':
                cooldownMs = error.retryAfterMs && error.retryAfterMs > exports.COOLDOWN_POLICY.rateLimitMaxMs
                    ? error.retryAfterMs
                    : (0, exports.nextPacificMidnight)(now) - now;
                break;
            case 'model_not_found':
                cooldownMs = exports.COOLDOWN_POLICY.modelUnavailableMs;
                break;
            case 'rate_limited':
                cooldownMs = clamp((_a = error.retryAfterMs) !== null && _a !== void 0 ? _a : exports.COOLDOWN_POLICY.rateLimitDefaultMs, exports.COOLDOWN_POLICY.rateLimitMinMs, exports.COOLDOWN_POLICY.rateLimitMaxMs);
                break;
            default: {
                // server_error, timeout, unknown → exponential backoff
                const backoff = exports.COOLDOWN_POLICY.backoffBaseMs * 2 ** Math.max(0, h.failureCount - 1);
                cooldownMs = Math.min(exports.COOLDOWN_POLICY.backoffMaxMs, Math.max(backoff, error.retryAfterMs || 0));
            }
        }
        h.status = 'cooldown';
        h.cooldownUntil = Math.max(h.cooldownUntil || 0, now + cooldownMs);
        return h;
    }
    snapshot(now = Date.now()) {
        let availableKeys = 0;
        let cooldownKeys = 0;
        let disabledKeys = 0;
        let nextRetryAt = null;
        const keys = [];
        this.health.forEach((h) => {
            this.refresh(h, now);
            if (h.status === 'available')
                availableKeys += 1;
            if (h.status === 'disabled')
                disabledKeys += 1;
            if (h.status === 'cooldown') {
                cooldownKeys += 1;
                if (h.cooldownUntil && (nextRetryAt === null || h.cooldownUntil < nextRetryAt))
                    nextRetryAt = h.cooldownUntil;
            }
            keys.push(Object.assign({}, h));
        });
        return { configuredKeys: this.size, availableKeys, cooldownKeys, disabledKeys, nextRetryAt, keys };
    }
}
exports.LLMKeyPool = LLMKeyPool;
