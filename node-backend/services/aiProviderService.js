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
exports.initializeAIProviders = exports.getAIStatus = exports.askExternalLLM = exports.determineActiveProvider = exports.setPreferredProvider = exports.getPreferredProvider = exports.getModel = exports.isAIEnabled = exports.reloadAIProviderConfig = exports.LLMUnavailableError = exports.PROVIDER_PREFERENCES = void 0;
const axios_1 = __importDefault(require("axios"));
const llmKeyPool_1 = require("./llmKeyPool");
exports.PROVIDER_PREFERENCES = ['auto', 'gemini', 'groq', 'openai', 'offline'];
const DEFAULT_ORDER = ['gemini', 'groq', 'openai'];
const DEFAULT_MODELS = {
    // Google retires older models for new projects first (gemini-1.5/2.5 return 404
    // "no longer available to new users"); 3.5 Flash works on new and existing projects.
    gemini: 'gemini-3.5-flash',
    groq: 'openai/gpt-oss-20b',
    openai: 'gpt-4o-mini',
};
const MAX_GEMINI_KEYS = 10;
const MIN_ATTEMPT_BUDGET_MS = 1500;
/** Error thrown when no external provider produced an answer. Contains no secrets. */
class LLMUnavailableError extends Error {
    constructor(code, attempts = []) {
        super(code);
        this.code = code;
        this.attempts = attempts;
        this.name = 'LLMUnavailableError';
    }
}
exports.LLMUnavailableError = LLMUnavailableError;
let state = null;
const readGeminiKeys = (env) => {
    const keys = [];
    for (let i = 1; i <= MAX_GEMINI_KEYS; i += 1) {
        const value = env[`GEMINI_API_KEY_${i}`];
        if (value && value.trim())
            keys.push(value.trim());
    }
    // Backward compatibility: legacy single-key variable (deduplicated by the pool).
    if (env.GEMINI_API_KEY && env.GEMINI_API_KEY.trim())
        keys.push(env.GEMINI_API_KEY.trim());
    return keys;
};
/** (Re)builds provider pools from process.env. Resets all runtime key health. */
const reloadAIProviderConfig = (env = process.env) => {
    var _a;
    state = {
        pools: {
            gemini: new llmKeyPool_1.LLMKeyPool('gemini', readGeminiKeys(env)),
            groq: new llmKeyPool_1.LLMKeyPool('groq', [env.GROQ_API_KEY || '']),
            openai: new llmKeyPool_1.LLMKeyPool('openai', [env.OPENAI_API_KEY || '']),
        },
        preferredOverride: (_a = state === null || state === void 0 ? void 0 : state.preferredOverride) !== null && _a !== void 0 ? _a : null,
    };
};
exports.reloadAIProviderConfig = reloadAIProviderConfig;
const getState = () => {
    if (!state)
        (0, exports.reloadAIProviderConfig)();
    return state;
};
const isAIEnabled = () => process.env.AI_ENABLED !== 'false';
exports.isAIEnabled = isAIEnabled;
const getModel = (provider) => {
    const envName = { gemini: 'GEMINI_MODEL', groq: 'GROQ_MODEL', openai: 'OPENAI_MODEL' }[provider];
    const value = (process.env[envName] || '').trim();
    return value || DEFAULT_MODELS[provider];
};
exports.getModel = getModel;
const numberFromEnv = (name, fallback, min, max) => {
    const parsed = Number(process.env[name]);
    return Number.isFinite(parsed) && parsed > 0 ? Math.min(max, Math.max(min, parsed)) : fallback;
};
const getPreferredProvider = () => {
    const override = getState().preferredOverride;
    if (override)
        return override;
    const fromEnv = String(process.env.AI_PROVIDER || 'auto').trim().toLowerCase();
    return exports.PROVIDER_PREFERENCES.includes(fromEnv) ? fromEnv : 'auto';
};
exports.getPreferredProvider = getPreferredProvider;
/** Admin-only runtime preference (validated by the controller). Never touches API keys. */
const setPreferredProvider = (provider) => {
    if (!exports.PROVIDER_PREFERENCES.includes(provider))
        throw new Error('INVALID_PROVIDER');
    getState().preferredOverride = provider;
};
exports.setPreferredProvider = setPreferredProvider;
const providerOrder = () => {
    const preferred = (0, exports.getPreferredProvider)();
    if (preferred === 'auto' || preferred === 'offline')
        return [...DEFAULT_ORDER];
    return [preferred, ...DEFAULT_ORDER.filter((p) => p !== preferred)];
};
/** First provider that currently has an eligible key (informational; no secrets). */
const determineActiveProvider = () => {
    if (!(0, exports.isAIEnabled)() || (0, exports.getPreferredProvider)() === 'offline') {
        return { provider: 'offline', model: 'rakshak-cyber-engine' };
    }
    const { pools } = getState();
    const now = Date.now();
    for (const provider of providerOrder()) {
        if (pools[provider].eligibleIds(now).length)
            return { provider, model: (0, exports.getModel)(provider) };
    }
    return { provider: 'offline', model: 'rakshak-cyber-engine' };
};
exports.determineActiveProvider = determineActiveProvider;
// ── Provider HTTP clients ───────────────────────────────────────────────────
const emptyResponse = () => Object.assign(new Error('AI_EMPTY_RESPONSE'), { code: 'AI_EMPTY_RESPONSE' });
const callOpenAICompatible = (url, apiKey, model, messages, timeoutMs) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c, _d;
    const response = yield axios_1.default.post(url, { model, messages, temperature: 0.3, max_tokens: 1500 }, {
        timeout: timeoutMs,
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    });
    const content = (_d = (_c = (_b = (_a = response.data) === null || _a === void 0 ? void 0 : _a.choices) === null || _b === void 0 ? void 0 : _b[0]) === null || _c === void 0 ? void 0 : _c.message) === null || _d === void 0 ? void 0 : _d.content;
    if (typeof content !== 'string' || !content.trim())
        throw emptyResponse();
    return content.trim();
});
/** Gemini requires alternating user/model turns that start with a user turn. */
const toGeminiContents = (messages) => {
    const contents = [];
    for (const m of messages) {
        if (m.role === 'system' || !m.content)
            continue;
        const role = m.role === 'assistant' ? 'model' : 'user';
        if (!contents.length && role === 'model')
            continue;
        const last = contents[contents.length - 1];
        if (last && last.role === role)
            last.parts[0].text += `\n\n${m.content}`;
        else
            contents.push({ role, parts: [{ text: m.content }] });
    }
    return contents;
};
const callGemini = (apiKey, model, messages, timeoutMs) => __awaiter(void 0, void 0, void 0, function* () {
    var _e, _f, _g, _h;
    const systemText = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n');
    const generationConfig = { temperature: 0.3, maxOutputTokens: 2048 };
    // Flash models "think" by default, which adds latency and consumes the output
    // budget; a chat assistant does not need deep reasoning.
    //  • Gemini 2.5 Flash: thinkingBudget 0 disables thinking (2.5 Pro cannot disable it)
    //  • Gemini 3.x+: thinkingLevel (GEMINI_THINKING_LEVEL, default "minimal"; "default" = model default)
    const thinkingLevel = (process.env.GEMINI_THINKING_LEVEL || 'minimal').trim().toLowerCase();
    if (/^gemini-2\.5-flash/.test(model)) {
        generationConfig.thinkingConfig = { thinkingBudget: 0 };
    }
    else if (/^gemini-([3-9]|\d{2,})/.test(model) && thinkingLevel !== 'default') {
        generationConfig.thinkingConfig = { thinkingLevel };
    }
    const body = { contents: toGeminiContents(messages), generationConfig };
    if (systemText)
        body.systemInstruction = { parts: [{ text: systemText }] };
    // Key is sent in the x-goog-api-key header — never in the URL (URLs end up in logs).
    const response = yield axios_1.default.post(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, body, { timeout: timeoutMs, headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey } });
    const parts = ((_h = (_g = (_f = (_e = response.data) === null || _e === void 0 ? void 0 : _e.candidates) === null || _f === void 0 ? void 0 : _f[0]) === null || _g === void 0 ? void 0 : _g.content) === null || _h === void 0 ? void 0 : _h.parts) || [];
    const text = parts
        .filter((p) => typeof (p === null || p === void 0 ? void 0 : p.text) === 'string' && !p.thought)
        .map((p) => p.text)
        .join('')
        .trim();
    if (!text)
        throw emptyResponse();
    return text;
});
const callProvider = (provider, apiKey, model, messages, timeoutMs) => {
    if (provider === 'gemini')
        return callGemini(apiKey, model, messages, timeoutMs);
    if (provider === 'groq')
        return callOpenAICompatible('https://api.groq.com/openai/v1/chat/completions', apiKey, model, messages, timeoutMs);
    return callOpenAICompatible('https://api.openai.com/v1/chat/completions', apiKey, model, messages, timeoutMs);
};
// ── Unified request handler with rotation + failover ────────────────────────
const askExternalLLM = (messages) => __awaiter(void 0, void 0, void 0, function* () {
    if (!(0, exports.isAIEnabled)())
        throw new LLMUnavailableError('AI_DISABLED');
    if ((0, exports.getPreferredProvider)() === 'offline')
        throw new LLMUnavailableError('OFFLINE_PREFERRED');
    const { pools } = getState();
    const order = providerOrder().filter((p) => pools[p].size > 0);
    if (!order.length)
        throw new LLMUnavailableError('NO_LLM_CONFIGURED');
    const perAttemptMs = numberFromEnv('AI_REQUEST_TIMEOUT_MS', 15000, 2000, 60000);
    const totalBudgetMs = numberFromEnv('AI_TOTAL_TIMEOUT_MS', 30000, 5000, 120000);
    const deadline = Date.now() + totalBudgetMs;
    const attempts = [];
    for (const provider of order) {
        const pool = pools[provider];
        const model = (0, exports.getModel)(provider);
        const tried = new Set();
        while (true) {
            const remaining = deadline - Date.now();
            if (remaining < MIN_ATTEMPT_BUDGET_MS)
                throw new LLMUnavailableError('ALL_PROVIDERS_FAILED', attempts);
            const pick = pool.pick(tried);
            if (!pick)
                break; // every key of this provider tried or cooling down
            tried.add(pick.id);
            const startedAt = Date.now();
            try {
                const answer = yield callProvider(provider, pick.apiKey, model, messages, Math.min(perAttemptMs, remaining));
                pool.reportSuccess(pick.id, startedAt);
                return { answer, provider, model, keyId: pick.id, failoverUsed: attempts.length > 0, attempts };
            }
            catch (err) {
                const classified = (0, llmKeyPool_1.classifyLLMError)(err);
                const health = pool.reportFailure(pick.id, classified, startedAt);
                attempts.push({ provider, keyId: pick.id, category: classified.category, httpStatus: classified.httpStatus });
                // Safe log line: identifiers and categories only — no key, no prompt content.
                const cooldown = (health === null || health === void 0 ? void 0 : health.status) === 'cooldown' && health.cooldownUntil
                    ? ` cooldown ${Math.round((health.cooldownUntil - Date.now()) / 1000)}s`
                    : (health === null || health === void 0 ? void 0 : health.status) === 'disabled' ? ' key disabled' : '';
                console.warn(`[AIProviderService] ${pick.id} (${model}) failed: ${classified.category}` +
                    `${classified.httpStatus ? ` HTTP ${classified.httpStatus}` : ''}${cooldown}`);
                if (!classified.retryWithNextKey)
                    break; // failure is not key specific → next provider
            }
        }
    }
    throw new LLMUnavailableError('ALL_PROVIDERS_FAILED', attempts);
});
exports.askExternalLLM = askExternalLLM;
const poolStatus = (snap, multiKey) => {
    if (!snap.configuredKeys)
        return 'unavailable';
    if (snap.availableKeys === snap.configuredKeys)
        return multiKey ? 'operational' : 'available';
    if (snap.availableKeys > 0)
        return 'degraded';
    if (snap.cooldownKeys > 0)
        return 'cooldown';
    return 'invalid';
};
/** Non-secret warning when the configured model is unavailable for some keys. */
const modelWarning = (provider, snap) => {
    const affected = snap.keys.filter((k) => k.lastErrorCategory === 'model_not_found' && k.status === 'cooldown').length;
    if (!affected)
        return {};
    return {
        warning: `Configured model "${(0, exports.getModel)(provider)}" is not available for ${affected} of ${snap.configuredKeys} key(s). Check ${provider.toUpperCase()}_MODEL.`,
    };
};
const toPublicKeys = (keys) => keys.map(({ id, status, lastSuccessAt, lastErrorCategory, cooldownUntil, failureCount }) => ({
    id,
    status,
    lastSuccessAt,
    lastErrorCategory,
    cooldownUntil,
    failureCount,
}));
const getAIStatus = (options = {}) => {
    var _a;
    const { pools } = getState();
    const enabled = (0, exports.isAIEnabled)();
    const active = (0, exports.determineActiveProvider)();
    const preferredProvider = (0, exports.getPreferredProvider)();
    const gemini = pools.gemini.snapshot();
    const groq = pools.groq.snapshot();
    const openai = pools.openai.snapshot();
    const single = (provider, snap) => (Object.assign(Object.assign({ configured: snap.configuredKeys > 0, status: poolStatus(snap, false), model: (0, exports.getModel)(provider), nextRetryAt: snap.nextRetryAt }, modelWarning(provider, snap)), (options.includeKeyDetails ? { keys: toPublicKeys(snap.keys) } : {})));
    const activeSnap = active.provider === 'offline' ? null : pools[active.provider].snapshot();
    return {
        // Legacy fields consumed by AIRakshakScreen
        enabled,
        activeProvider: active.provider,
        available: true,
        configuredProviders: {
            groq: groq.configuredKeys > 0,
            gemini: gemini.configuredKeys > 0,
            openai: openai.configuredKeys > 0,
        },
        activeModel: active.model,
        cooldownUntil: (_a = activeSnap === null || activeSnap === void 0 ? void 0 : activeSnap.nextRetryAt) !== null && _a !== void 0 ? _a : null,
        // Operational detail
        aiEnabled: enabled,
        preferredProvider,
        providers: {
            gemini: Object.assign(Object.assign({ configuredKeys: gemini.configuredKeys, availableKeys: gemini.availableKeys, cooldownKeys: gemini.cooldownKeys, disabledKeys: gemini.disabledKeys, status: poolStatus(gemini, true), model: (0, exports.getModel)('gemini'), nextRetryAt: gemini.nextRetryAt }, modelWarning('gemini', gemini)), (options.includeKeyDetails ? { keys: toPublicKeys(gemini.keys) } : {})),
            groq: single('groq', groq),
            openai: single('openai', openai),
            offline: { status: 'available', model: 'rakshak-cyber-engine-v2' },
        },
        quotaNote: 'Gemini rate limits are enforced per Google Cloud project. Keys that belong to the same project share one quota, so rotating them improves resilience but does not increase total capacity.',
    };
};
exports.getAIStatus = getAIStatus;
// ── Startup validation (no generation quota consumed) ───────────────────────
const validateKey = (provider, apiKey, model) => __awaiter(void 0, void 0, void 0, function* () {
    const timeout = 8000;
    if (provider === 'gemini') {
        // countTokens (not models.get) is used because it reflects per-project model
        // availability — e.g. models retired "for new users" — without generating text.
        yield axios_1.default.post(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:countTokens`, { contents: [{ role: 'user', parts: [{ text: 'ping' }] }] }, { timeout, headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey } });
    }
    else {
        const base = provider === 'groq' ? 'https://api.groq.com/openai/v1' : 'https://api.openai.com/v1';
        // Model ids may contain "/" (e.g. "openai/gpt-oss-20b"), which must stay a path separator.
        const modelPath = model.split('/').map(encodeURIComponent).join('/');
        yield axios_1.default.get(`${base}/models/${modelPath}`, { timeout, headers: { Authorization: `Bearer ${apiKey}` } });
    }
});
/**
 * Logs the AI configuration and verifies each key + model with a metadata
 * request (Gemini countTokens / OpenAI-compatible models.get). Invalid keys and
 * keys that cannot use the configured model are taken out of rotation before
 * any user request.
 * Never throws; network problems only produce a warning.
 */
const initializeAIProviders = () => __awaiter(void 0, void 0, void 0, function* () {
    (0, exports.reloadAIProviderConfig)();
    const { pools } = getState();
    const counts = `gemini keys=${pools.gemini.size}, groq=${pools.groq.size ? 'yes' : 'no'}, openai=${pools.openai.size ? 'yes' : 'no'}`;
    if (!(0, exports.isAIEnabled)()) {
        console.log(`[AIProviderService] AI_ENABLED=false — external providers disabled (${counts}). Offline engine active.`);
        return;
    }
    console.log(`[AIProviderService] Configured providers: ${counts}; preference=${(0, exports.getPreferredProvider)()}`);
    if (!pools.gemini.size && !pools.groq.size && !pools.openai.size) {
        console.warn('[AIProviderService] No LLM API keys configured — AI RAKSHAK will use the offline Cyber Intelligence Engine.');
        return;
    }
    if (process.env.AI_STARTUP_VALIDATION === 'false')
        return;
    const checks = [];
    Object.keys(pools).forEach((provider) => {
        const pool = pools[provider];
        const model = (0, exports.getModel)(provider);
        const exclude = new Set();
        let pick = pool.pick(exclude);
        while (pick) {
            const { id, apiKey } = pick;
            exclude.add(id);
            const startedAt = Date.now();
            checks.push(validateKey(provider, apiKey, model)
                .then(() => console.log(`[AIProviderService] ${id} verified (model ${model})`))
                .catch((err) => {
                const classified = (0, llmKeyPool_1.classifyLLMError)(err);
                if (classified.category === 'invalid_key' || classified.category === 'permission_denied') {
                    pool.reportFailure(id, classified, startedAt);
                    console.warn(`[AIProviderService] ${id} rejected by ${provider} (${classified.category}) — disabled until configuration is corrected.`);
                }
                else if (classified.category === 'model_not_found') {
                    pool.reportFailure(id, classified, startedAt);
                    console.warn(`[AIProviderService] ${id}: model "${model}" not available for this key/project — check ${provider.toUpperCase()}_MODEL. Key paused and re-checked hourly.`);
                }
                else {
                    console.warn(`[AIProviderService] ${id} could not be verified at startup (${classified.category}); will retry on demand.`);
                }
            }));
            pick = pool.pick(exclude);
        }
    });
    yield Promise.all(checks);
});
exports.initializeAIProviders = initializeAIProviders;
