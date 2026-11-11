import axios from 'axios';
import { LLMKeyPool, classifyLLMError, KeyErrorCategory, KeyHealth, PoolSnapshot } from './llmKeyPool';

/**
 * ── AI Provider Service ─────────────────────────────────────────────────────
 * Single gateway for external LLM calls used by AI RAKSHAK.
 *
 * Provider chain (per request):
 *   preferred provider (if set) → Gemini key pool → Groq → OpenAI
 * Each configured key is attempted at most once per request, bounded by an
 * overall time budget. If every provider fails, the caller (aiOrchestrator)
 * falls back to the offline Cyber Intelligence Engine.
 *
 * All API keys come exclusively from backend environment variables. They are
 * never returned to clients, logged, or persisted.
 */

export type MessageRole = 'system' | 'user' | 'assistant';
export interface ChatMessage {
  role: MessageRole;
  content: string;
}

export type LLMProvider = 'groq' | 'gemini' | 'openai' | 'offline';
export type ExternalProvider = Exclude<LLMProvider, 'offline'>;
export type ProviderPreference = ExternalProvider | 'offline' | 'auto';

export const PROVIDER_PREFERENCES: ProviderPreference[] = ['auto', 'gemini', 'groq', 'openai', 'offline'];
const DEFAULT_ORDER: ExternalProvider[] = ['gemini', 'groq', 'openai'];

const DEFAULT_MODELS: Record<ExternalProvider, string> = {
  // Google retires older models for new projects first (gemini-1.5/2.5 return 404
  // "no longer available to new users"); 3.5 Flash works on new and existing projects.
  gemini: 'gemini-3.5-flash',
  groq: 'openai/gpt-oss-20b',
  openai: 'gpt-4o-mini',
};

const MAX_GEMINI_KEYS = 10;
const MIN_ATTEMPT_BUDGET_MS = 1_500;

export interface LLMAttempt {
  provider: ExternalProvider;
  keyId: string;
  category: KeyErrorCategory;
  httpStatus: number | null;
}

export interface LLMResult {
  answer: string;
  provider: ExternalProvider;
  model: string;
  keyId: string;
  /** True when at least one earlier key/provider failed before this answer. */
  failoverUsed: boolean;
  attempts: LLMAttempt[];
}

/** Error thrown when no external provider produced an answer. Contains no secrets. */
export class LLMUnavailableError extends Error {
  constructor(readonly code: 'AI_DISABLED' | 'OFFLINE_PREFERRED' | 'NO_LLM_CONFIGURED' | 'ALL_PROVIDERS_FAILED', readonly attempts: LLMAttempt[] = []) {
    super(code);
    this.name = 'LLMUnavailableError';
  }
}

// ── Configuration (lazy, environment driven) ────────────────────────────────
interface ProviderState {
  pools: Record<ExternalProvider, LLMKeyPool>;
  preferredOverride: ProviderPreference | null; // admin runtime preference (no secrets)
}

let state: ProviderState | null = null;

const readGeminiKeys = (env: NodeJS.ProcessEnv): string[] => {
  const keys: string[] = [];
  for (let i = 1; i <= MAX_GEMINI_KEYS; i += 1) {
    const value = env[`GEMINI_API_KEY_${i}`];
    if (value && value.trim()) keys.push(value.trim());
  }
  // Backward compatibility: legacy single-key variable (deduplicated by the pool).
  if (env.GEMINI_API_KEY && env.GEMINI_API_KEY.trim()) keys.push(env.GEMINI_API_KEY.trim());
  return keys;
};

/** (Re)builds provider pools from process.env. Resets all runtime key health. */
export const reloadAIProviderConfig = (env: NodeJS.ProcessEnv = process.env): void => {
  state = {
    pools: {
      gemini: new LLMKeyPool('gemini', readGeminiKeys(env)),
      groq: new LLMKeyPool('groq', [env.GROQ_API_KEY || '']),
      openai: new LLMKeyPool('openai', [env.OPENAI_API_KEY || '']),
    },
    preferredOverride: state?.preferredOverride ?? null,
  };
};

const getState = (): ProviderState => {
  if (!state) reloadAIProviderConfig();
  return state as ProviderState;
};

export const isAIEnabled = (): boolean => process.env.AI_ENABLED !== 'false';

export const getModel = (provider: ExternalProvider): string => {
  const envName = { gemini: 'GEMINI_MODEL', groq: 'GROQ_MODEL', openai: 'OPENAI_MODEL' }[provider];
  const value = (process.env[envName] || '').trim();
  return value || DEFAULT_MODELS[provider];
};

const numberFromEnv = (name: string, fallback: number, min: number, max: number): number => {
  const parsed = Number(process.env[name]);
  return Number.isFinite(parsed) && parsed > 0 ? Math.min(max, Math.max(min, parsed)) : fallback;
};

export const getPreferredProvider = (): ProviderPreference => {
  const override = getState().preferredOverride;
  if (override) return override;
  const fromEnv = String(process.env.AI_PROVIDER || 'auto').trim().toLowerCase() as ProviderPreference;
  return PROVIDER_PREFERENCES.includes(fromEnv) ? fromEnv : 'auto';
};

/** Admin-only runtime preference (validated by the controller). Never touches API keys. */
export const setPreferredProvider = (provider: ProviderPreference): void => {
  if (!PROVIDER_PREFERENCES.includes(provider)) throw new Error('INVALID_PROVIDER');
  getState().preferredOverride = provider;
};

const providerOrder = (): ExternalProvider[] => {
  const preferred = getPreferredProvider();
  if (preferred === 'auto' || preferred === 'offline') return [...DEFAULT_ORDER];
  return [preferred, ...DEFAULT_ORDER.filter((p) => p !== preferred)];
};

/** First provider that currently has an eligible key (informational; no secrets). */
export const determineActiveProvider = (): { provider: LLMProvider; model: string } => {
  if (!isAIEnabled() || getPreferredProvider() === 'offline') {
    return { provider: 'offline', model: 'rakshak-cyber-engine' };
  }
  const { pools } = getState();
  const now = Date.now();
  for (const provider of providerOrder()) {
    if (pools[provider].eligibleIds(now).length) return { provider, model: getModel(provider) };
  }
  return { provider: 'offline', model: 'rakshak-cyber-engine' };
};

// ── Provider HTTP clients ───────────────────────────────────────────────────
const emptyResponse = (): Error => Object.assign(new Error('AI_EMPTY_RESPONSE'), { code: 'AI_EMPTY_RESPONSE' });

const callOpenAICompatible = async (
  url: string,
  apiKey: string,
  model: string,
  messages: ChatMessage[],
  timeoutMs: number
): Promise<string> => {
  const response = await axios.post(
    url,
    { model, messages, temperature: 0.3, max_tokens: 1500 },
    {
      timeout: timeoutMs,
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    }
  );
  const content = response.data?.choices?.[0]?.message?.content;
  if (typeof content !== 'string' || !content.trim()) throw emptyResponse();
  return content.trim();
};

/** Gemini requires alternating user/model turns that start with a user turn. */
const toGeminiContents = (messages: ChatMessage[]) => {
  const contents: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }> = [];
  for (const m of messages) {
    if (m.role === 'system' || !m.content) continue;
    const role = m.role === 'assistant' ? 'model' : 'user';
    if (!contents.length && role === 'model') continue;
    const last = contents[contents.length - 1];
    if (last && last.role === role) last.parts[0].text += `\n\n${m.content}`;
    else contents.push({ role, parts: [{ text: m.content }] });
  }
  return contents;
};

const callGemini = async (apiKey: string, model: string, messages: ChatMessage[], timeoutMs: number): Promise<string> => {
  const systemText = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n');
  const generationConfig: Record<string, unknown> = { temperature: 0.3, maxOutputTokens: 2048 };
  // Flash models "think" by default, which adds latency and consumes the output
  // budget; a chat assistant does not need deep reasoning.
  //  • Gemini 2.5 Flash: thinkingBudget 0 disables thinking (2.5 Pro cannot disable it)
  //  • Gemini 3.x+: thinkingLevel (GEMINI_THINKING_LEVEL, default "minimal"; "default" = model default)
  const thinkingLevel = (process.env.GEMINI_THINKING_LEVEL || 'minimal').trim().toLowerCase();
  if (/^gemini-2\.5-flash/.test(model)) {
    generationConfig.thinkingConfig = { thinkingBudget: 0 };
  } else if (/^gemini-([3-9]|\d{2,})/.test(model) && thinkingLevel !== 'default') {
    generationConfig.thinkingConfig = { thinkingLevel };
  }

  const body: Record<string, unknown> = { contents: toGeminiContents(messages), generationConfig };
  if (systemText) body.systemInstruction = { parts: [{ text: systemText }] };

  // Key is sent in the x-goog-api-key header — never in the URL (URLs end up in logs).
  const response = await axios.post(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    body,
    { timeout: timeoutMs, headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey } }
  );

  const parts: any[] = response.data?.candidates?.[0]?.content?.parts || [];
  const text = parts
    .filter((p) => typeof p?.text === 'string' && !p.thought)
    .map((p) => p.text)
    .join('')
    .trim();
  if (!text) throw emptyResponse();
  return text;
};

const callProvider = (provider: ExternalProvider, apiKey: string, model: string, messages: ChatMessage[], timeoutMs: number) => {
  if (provider === 'gemini') return callGemini(apiKey, model, messages, timeoutMs);
  if (provider === 'groq') return callOpenAICompatible('https://api.groq.com/openai/v1/chat/completions', apiKey, model, messages, timeoutMs);
  return callOpenAICompatible('https://api.openai.com/v1/chat/completions', apiKey, model, messages, timeoutMs);
};

// ── Unified request handler with rotation + failover ────────────────────────
export const askExternalLLM = async (messages: ChatMessage[]): Promise<LLMResult> => {
  if (!isAIEnabled()) throw new LLMUnavailableError('AI_DISABLED');
  if (getPreferredProvider() === 'offline') throw new LLMUnavailableError('OFFLINE_PREFERRED');

  const { pools } = getState();
  const order = providerOrder().filter((p) => pools[p].size > 0);
  if (!order.length) throw new LLMUnavailableError('NO_LLM_CONFIGURED');

  const perAttemptMs = numberFromEnv('AI_REQUEST_TIMEOUT_MS', 15_000, 2_000, 60_000);
  const totalBudgetMs = numberFromEnv('AI_TOTAL_TIMEOUT_MS', 30_000, 5_000, 120_000);
  const deadline = Date.now() + totalBudgetMs;
  const attempts: LLMAttempt[] = [];

  for (const provider of order) {
    const pool = pools[provider];
    const model = getModel(provider);
    const tried = new Set<string>();

    while (true) {
      const remaining = deadline - Date.now();
      if (remaining < MIN_ATTEMPT_BUDGET_MS) throw new LLMUnavailableError('ALL_PROVIDERS_FAILED', attempts);

      const pick = pool.pick(tried);
      if (!pick) break; // every key of this provider tried or cooling down
      tried.add(pick.id);

      const startedAt = Date.now();
      try {
        const answer = await callProvider(provider, pick.apiKey, model, messages, Math.min(perAttemptMs, remaining));
        pool.reportSuccess(pick.id, startedAt);
        return { answer, provider, model, keyId: pick.id, failoverUsed: attempts.length > 0, attempts };
      } catch (err) {
        const classified = classifyLLMError(err);
        const health = pool.reportFailure(pick.id, classified, startedAt);
        attempts.push({ provider, keyId: pick.id, category: classified.category, httpStatus: classified.httpStatus });

        // Safe log line: identifiers and categories only — no key, no prompt content.
        const cooldown = health?.status === 'cooldown' && health.cooldownUntil
          ? ` cooldown ${Math.round((health.cooldownUntil - Date.now()) / 1000)}s`
          : health?.status === 'disabled' ? ' key disabled' : '';
        console.warn(
          `[AIProviderService] ${pick.id} (${model}) failed: ${classified.category}` +
            `${classified.httpStatus ? ` HTTP ${classified.httpStatus}` : ''}${cooldown}`
        );

        if (!classified.retryWithNextKey) break; // failure is not key specific → next provider
      }
    }
  }

  throw new LLMUnavailableError('ALL_PROVIDERS_FAILED', attempts);
};

// ── Status reporting (no secrets) ───────────────────────────────────────────
type PublicKeyHealth = Pick<KeyHealth, 'id' | 'status' | 'lastSuccessAt' | 'lastErrorCategory' | 'cooldownUntil' | 'failureCount'>;

const poolStatus = (snap: PoolSnapshot, multiKey: boolean): string => {
  if (!snap.configuredKeys) return 'unavailable';
  if (snap.availableKeys === snap.configuredKeys) return multiKey ? 'operational' : 'available';
  if (snap.availableKeys > 0) return 'degraded';
  if (snap.cooldownKeys > 0) return 'cooldown';
  return 'invalid';
};

/** Non-secret warning when the configured model is unavailable for some keys. */
const modelWarning = (provider: ExternalProvider, snap: PoolSnapshot): Record<string, string> => {
  const affected = snap.keys.filter((k) => k.lastErrorCategory === 'model_not_found' && k.status === 'cooldown').length;
  if (!affected) return {};
  return {
    warning: `Configured model "${getModel(provider)}" is not available for ${affected} of ${snap.configuredKeys} key(s). Check ${provider.toUpperCase()}_MODEL.`,
  };
};

const toPublicKeys = (keys: KeyHealth[]): PublicKeyHealth[] =>
  keys.map(({ id, status, lastSuccessAt, lastErrorCategory, cooldownUntil, failureCount }) => ({
    id,
    status,
    lastSuccessAt,
    lastErrorCategory,
    cooldownUntil,
    failureCount,
  }));

export const getAIStatus = (options: { includeKeyDetails?: boolean } = {}) => {
  const { pools } = getState();
  const enabled = isAIEnabled();
  const active = determineActiveProvider();
  const preferredProvider = getPreferredProvider();
  const gemini = pools.gemini.snapshot();
  const groq = pools.groq.snapshot();
  const openai = pools.openai.snapshot();

  const single = (provider: 'groq' | 'openai', snap: PoolSnapshot) => ({
    configured: snap.configuredKeys > 0,
    status: poolStatus(snap, false),
    model: getModel(provider),
    nextRetryAt: snap.nextRetryAt,
    ...modelWarning(provider, snap),
    ...(options.includeKeyDetails ? { keys: toPublicKeys(snap.keys) } : {}),
  });

  const activeSnap = active.provider === 'offline' ? null : pools[active.provider].snapshot();

  return {
    // Legacy fields consumed by AIRakshakScreen
    enabled,
    activeProvider: active.provider,
    available: true, // the offline Cyber Intelligence Engine always answers
    configuredProviders: {
      groq: groq.configuredKeys > 0,
      gemini: gemini.configuredKeys > 0,
      openai: openai.configuredKeys > 0,
    },
    activeModel: active.model,
    cooldownUntil: activeSnap?.nextRetryAt ?? null,
    // Operational detail
    aiEnabled: enabled,
    preferredProvider,
    providers: {
      gemini: {
        configuredKeys: gemini.configuredKeys,
        availableKeys: gemini.availableKeys,
        cooldownKeys: gemini.cooldownKeys,
        disabledKeys: gemini.disabledKeys,
        status: poolStatus(gemini, true),
        model: getModel('gemini'),
        nextRetryAt: gemini.nextRetryAt,
        ...modelWarning('gemini', gemini),
        ...(options.includeKeyDetails ? { keys: toPublicKeys(gemini.keys) } : {}),
      },
      groq: single('groq', groq),
      openai: single('openai', openai),
      offline: { status: 'available', model: 'rakshak-cyber-engine-v2' },
    },
    quotaNote:
      'Gemini rate limits are enforced per Google Cloud project. Keys that belong to the same project share one quota, so rotating them improves resilience but does not increase total capacity.',
  };
};

// ── Startup validation (no generation quota consumed) ───────────────────────
const validateKey = async (provider: ExternalProvider, apiKey: string, model: string): Promise<void> => {
  const timeout = 8_000;
  if (provider === 'gemini') {
    // countTokens (not models.get) is used because it reflects per-project model
    // availability — e.g. models retired "for new users" — without generating text.
    await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:countTokens`,
      { contents: [{ role: 'user', parts: [{ text: 'ping' }] }] },
      { timeout, headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey } }
    );
  } else {
    const base = provider === 'groq' ? 'https://api.groq.com/openai/v1' : 'https://api.openai.com/v1';
    // Model ids may contain "/" (e.g. "openai/gpt-oss-20b"), which must stay a path separator.
    const modelPath = model.split('/').map(encodeURIComponent).join('/');
    await axios.get(`${base}/models/${modelPath}`, { timeout, headers: { Authorization: `Bearer ${apiKey}` } });
  }
};

/**
 * Logs the AI configuration and verifies each key + model with a metadata
 * request (Gemini countTokens / OpenAI-compatible models.get). Invalid keys and
 * keys that cannot use the configured model are taken out of rotation before
 * any user request.
 * Never throws; network problems only produce a warning.
 */
export const initializeAIProviders = async (): Promise<void> => {
  reloadAIProviderConfig();
  const { pools } = getState();
  const counts = `gemini keys=${pools.gemini.size}, groq=${pools.groq.size ? 'yes' : 'no'}, openai=${pools.openai.size ? 'yes' : 'no'}`;

  if (!isAIEnabled()) {
    console.log(`[AIProviderService] AI_ENABLED=false — external providers disabled (${counts}). Offline engine active.`);
    return;
  }
  console.log(`[AIProviderService] Configured providers: ${counts}; preference=${getPreferredProvider()}`);
  if (!pools.gemini.size && !pools.groq.size && !pools.openai.size) {
    console.warn('[AIProviderService] No LLM API keys configured — AI RAKSHAK will use the offline Cyber Intelligence Engine.');
    return;
  }
  if (process.env.AI_STARTUP_VALIDATION === 'false') return;

  const checks: Promise<void>[] = [];
  (Object.keys(pools) as ExternalProvider[]).forEach((provider) => {
    const pool = pools[provider];
    const model = getModel(provider);
    const exclude = new Set<string>();
    let pick = pool.pick(exclude);
    while (pick) {
      const { id, apiKey } = pick;
      exclude.add(id);
      const startedAt = Date.now();
      checks.push(
        validateKey(provider, apiKey, model)
          .then(() => console.log(`[AIProviderService] ${id} verified (model ${model})`))
          .catch((err) => {
            const classified = classifyLLMError(err);
            if (classified.category === 'invalid_key' || classified.category === 'permission_denied') {
              pool.reportFailure(id, classified, startedAt);
              console.warn(`[AIProviderService] ${id} rejected by ${provider} (${classified.category}) — disabled until configuration is corrected.`);
            } else if (classified.category === 'model_not_found') {
              pool.reportFailure(id, classified, startedAt);
              console.warn(`[AIProviderService] ${id}: model "${model}" not available for this key/project — check ${provider.toUpperCase()}_MODEL. Key paused and re-checked hourly.`);
            } else {
              console.warn(`[AIProviderService] ${id} could not be verified at startup (${classified.category}); will retry on demand.`);
            }
          })
      );
      pick = pool.pick(exclude);
    }
  });
  await Promise.all(checks);
};
