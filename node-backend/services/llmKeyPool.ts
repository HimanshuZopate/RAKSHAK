import { randomInt } from 'crypto';

/**
 * ── LLM API Key Pool ────────────────────────────────────────────────────────
 * Runtime health tracking, error classification and cooldown management for
 * LLM provider API keys. Used by aiProviderService for:
 *   • Gemini  — a pool of several keys (GEMINI_API_KEY_1..N), random rotation
 *   • Groq / OpenAI — single-key pools (same health/cooldown semantics)
 *
 * SECURITY: secret key values live only in a private Map inside each pool.
 * They are never returned by snapshot(), never logged and never persisted.
 * Keys are referenced everywhere else by a non-secret identifier such as
 * "gemini-key-2".
 */

export type KeyErrorCategory =
  | 'quota_exhausted' // daily / long-window quota used up (RESOURCE_EXHAUSTED, PerDay quota)
  | 'rate_limited' // short-window limit (requests/tokens per minute)
  | 'server_error' // 500/502/503/504 — provider overloaded or unavailable
  | 'timeout' // request exceeded our timeout
  | 'network' // DNS / connection failure — not key specific
  | 'invalid_key' // key malformed, revoked or unknown
  | 'permission_denied' // key valid but not allowed to use this API/model
  | 'model_not_found' // configured model not available for this key/project
  | 'bad_request' // request payload rejected — not key specific
  | 'empty_response' // provider answered without usable text (e.g. safety block)
  | 'unknown';

export interface ClassifiedLLMError {
  category: KeyErrorCategory;
  httpStatus: number | null;
  /** Failure is attributable to this key → update its health. */
  keyScoped: boolean;
  /** Trying another key of the same provider may succeed. */
  retryWithNextKey: boolean;
  /** Provider supplied wait hint (Retry-After header or google.rpc.RetryInfo). */
  retryAfterMs: number | null;
}

export type KeyStatus = 'available' | 'cooldown' | 'disabled';

export interface KeyHealth {
  id: string;
  status: KeyStatus;
  lastSuccessAt: number | null;
  lastFailureAt: number | null;
  lastErrorCategory: KeyErrorCategory | null;
  cooldownUntil: number | null;
  failureCount: number; // consecutive temporary failures (reset on success)
}

export interface PoolSnapshot {
  configuredKeys: number;
  availableKeys: number;
  cooldownKeys: number;
  disabledKeys: number;
  nextRetryAt: number | null;
  keys: KeyHealth[];
}

// ── Cooldown policy ─────────────────────────────────────────────────────────
export const COOLDOWN_POLICY = {
  rateLimitDefaultMs: 60_000, // when a 429 carries no retry hint
  rateLimitMinMs: 5_000,
  rateLimitMaxMs: 15 * 60_000,
  backoffBaseMs: 5_000, // server errors / timeouts: 5s, 10s, 20s ...
  backoffMaxMs: 5 * 60_000,
  quotaFallbackMs: 60 * 60_000, // used if the daily reset time cannot be computed
  modelUnavailableMs: 60 * 60_000, // key cannot serve the configured model; re-check hourly
};

/** Gemini daily quotas reset at midnight Pacific time. Adds a 1 minute safety buffer. */
export const nextPacificMidnight = (now: number): number => {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: 'America/Los_Angeles',
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).formatToParts(new Date(now));
    const get = (type: string) => Number(parts.find((p) => p.type === type)?.value || 0);
    const hour = get('hour') % 24;
    const elapsedMs = (hour * 3600 + get('minute') * 60 + get('second')) * 1000;
    return now + (24 * 3600 * 1000 - elapsedMs) + 60_000;
  } catch {
    return now + COOLDOWN_POLICY.quotaFallbackMs;
  }
};

/** Parses "12s", "1.5s" (google.protobuf.Duration JSON form). */
const parseDurationMs = (value: unknown): number | null => {
  if (typeof value !== 'string') return null;
  const match = value.trim().match(/^(\d+(?:\.\d+)?)s$/);
  return match ? Math.round(parseFloat(match[1]) * 1000) : null;
};

/** Parses a Retry-After header (delta-seconds or HTTP-date). */
const parseRetryAfterHeader = (value: unknown, now: number): number | null => {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const raw = String(value).trim();
  if (/^\d+(?:\.\d+)?$/.test(raw)) return Math.round(parseFloat(raw) * 1000);
  const date = Date.parse(raw);
  return Number.isNaN(date) ? null : Math.max(0, date - now);
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

/**
 * Inspects an axios-style error (or an internal Error with a code) and decides
 * what went wrong. Understands Google's google.rpc error details (QuotaFailure,
 * RetryInfo, ErrorInfo) and OpenAI-compatible error bodies (Groq, OpenAI).
 */
export const classifyLLMError = (err: any, now = Date.now()): ClassifiedLLMError => {
  const result = (
    category: KeyErrorCategory,
    keyScoped: boolean,
    retryWithNextKey: boolean,
    httpStatus: number | null = null,
    retryAfterMs: number | null = null
  ): ClassifiedLLMError => ({ category, keyScoped, retryWithNextKey, httpStatus, retryAfterMs });

  if (err?.code === 'AI_EMPTY_RESPONSE' || err?.message === 'AI_EMPTY_RESPONSE') {
    return result('empty_response', false, false);
  }

  const response = err?.response;
  if (!response) {
    const code = String(err?.code || '');
    const message = String(err?.message || '');
    if (code === 'ECONNABORTED' || code === 'ETIMEDOUT' || code === 'ERR_CANCELED' || /timeout/i.test(message)) {
      return result('timeout', true, true);
    }
    if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'EHOSTUNREACH'].includes(code)) {
      // Network-level failure affects every key of the provider equally.
      return result('network', false, false);
    }
    return result('unknown', true, true);
  }

  const status: number = Number(response.status) || 0;
  const body = response.data || {};
  const apiError = body.error || {};
  const message: string = String(apiError.message || body.message || '');
  const statusText: string = String(apiError.status || apiError.code || apiError.type || '');
  const details: any[] = Array.isArray(apiError.details) ? apiError.details : [];
  const detailOfType = (suffix: string) => details.find((d) => String(d?.['@type'] || '').endsWith(suffix));

  const headerRetry = parseRetryAfterHeader(response.headers?.['retry-after'], now);
  const rpcRetry = parseDurationMs(detailOfType('RetryInfo')?.retryDelay);
  const retryAfterMs = rpcRetry ?? headerRetry;

  if (status === 429 || /RESOURCE_EXHAUSTED/i.test(statusText)) {
    const violations: any[] = detailOfType('QuotaFailure')?.violations || [];
    const quotaIds = violations.map((v) => `${v?.quotaId || ''} ${v?.quotaMetric || ''}`).join(' ');
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

/**
 * A pool of API keys for one provider.
 */
export class LLMKeyPool {
  private readonly secrets = new Map<string, string>();
  private readonly health = new Map<string, KeyHealth>();

  constructor(readonly provider: string, keys: string[]) {
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

  get size(): number {
    return this.secrets.size;
  }

  /** Moves keys whose cooldown has expired back to "available". */
  private refresh(h: KeyHealth, now: number): void {
    if (h.status === 'cooldown' && (h.cooldownUntil || 0) <= now) {
      h.status = 'available';
      h.cooldownUntil = null;
    }
  }

  eligibleIds(now = Date.now(), exclude: Set<string> = new Set()): string[] {
    const ids: string[] = [];
    this.health.forEach((h) => {
      this.refresh(h, now);
      if (h.status === 'available' && !exclude.has(h.id)) ids.push(h.id);
    });
    return ids;
  }

  /** Randomly selects an available key that has not been tried yet for this request. */
  pick(exclude: Set<string>, now = Date.now()): { id: string; apiKey: string } | null {
    const ids = this.eligibleIds(now, exclude);
    if (!ids.length) return null;
    const id = ids.length === 1 ? ids[0] : ids[randomInt(ids.length)];
    return { id, apiKey: this.secrets.get(id) as string };
  }

  reportSuccess(id: string, attemptStartedAt: number, now = Date.now()): void {
    const h = this.health.get(id);
    if (!h) return;
    h.lastSuccessAt = now;
    // A concurrent request may have recorded a failure *after* this attempt
    // started (e.g. the per-minute quota ran out meanwhile). Keep that newer state.
    if (h.status === 'disabled' || (h.lastFailureAt !== null && h.lastFailureAt >= attemptStartedAt)) return;
    h.status = 'available';
    h.cooldownUntil = null;
    h.failureCount = 0;
    h.lastErrorCategory = null;
  }

  reportFailure(id: string, error: ClassifiedLLMError, attemptStartedAt: number, now = Date.now()): KeyHealth | null {
    const h = this.health.get(id);
    if (!h || !error.keyScoped) return h || null;

    // If a parallel request already penalised this key after our attempt began,
    // merge instead of counting the same incident twice.
    const alreadyRecorded = h.lastFailureAt !== null && h.lastFailureAt >= attemptStartedAt;

    h.lastFailureAt = now;
    h.lastErrorCategory = error.category;
    if (h.status === 'disabled') return h;

    if (error.category === 'invalid_key' || error.category === 'permission_denied') {
      h.status = 'disabled'; // stays disabled until the configuration is corrected (restart)
      h.cooldownUntil = null;
      return h;
    }

    if (!alreadyRecorded) h.failureCount += 1;

    let cooldownMs: number;
    switch (error.category) {
      case 'quota_exhausted':
        cooldownMs = error.retryAfterMs && error.retryAfterMs > COOLDOWN_POLICY.rateLimitMaxMs
          ? error.retryAfterMs
          : nextPacificMidnight(now) - now;
        break;
      case 'model_not_found':
        cooldownMs = COOLDOWN_POLICY.modelUnavailableMs;
        break;
      case 'rate_limited':
        cooldownMs = clamp(
          error.retryAfterMs ?? COOLDOWN_POLICY.rateLimitDefaultMs,
          COOLDOWN_POLICY.rateLimitMinMs,
          COOLDOWN_POLICY.rateLimitMaxMs
        );
        break;
      default: {
        // server_error, timeout, unknown → exponential backoff
        const backoff = COOLDOWN_POLICY.backoffBaseMs * 2 ** Math.max(0, h.failureCount - 1);
        cooldownMs = Math.min(COOLDOWN_POLICY.backoffMaxMs, Math.max(backoff, error.retryAfterMs || 0));
      }
    }

    h.status = 'cooldown';
    h.cooldownUntil = Math.max(h.cooldownUntil || 0, now + cooldownMs);
    return h;
  }

  snapshot(now = Date.now()): PoolSnapshot {
    let availableKeys = 0;
    let cooldownKeys = 0;
    let disabledKeys = 0;
    let nextRetryAt: number | null = null;
    const keys: KeyHealth[] = [];

    this.health.forEach((h) => {
      this.refresh(h, now);
      if (h.status === 'available') availableKeys += 1;
      if (h.status === 'disabled') disabledKeys += 1;
      if (h.status === 'cooldown') {
        cooldownKeys += 1;
        if (h.cooldownUntil && (nextRetryAt === null || h.cooldownUntil < nextRetryAt)) nextRetryAt = h.cooldownUntil;
      }
      keys.push({ ...h });
    });

    return { configuredKeys: this.size, availableKeys, cooldownKeys, disabledKeys, nextRetryAt, keys };
  }
}
