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
exports.configureAI = exports.recommendations = exports.explain = exports.chat = exports.aiStatus = void 0;
const aiOrchestrator_1 = require("../services/aiOrchestrator");
const aiProviderService_1 = require("../services/aiProviderService");
const auditService_1 = require("../services/auditService");
const auditLog_model_1 = __importDefault(require("../model/auditLog.model"));
const MAX_QUESTION_CHARS = 2000;
const MAX_CONTEXT_CHARS = 4000;
const MAX_HISTORY_ITEMS = 50;
const questionFrom = (req) => { var _a; return typeof ((_a = req.body) === null || _a === void 0 ? void 0 : _a.question) === 'string' ? req.body.question.trim() : ''; };
const isAdmin = (req) => { var _a; return ((_a = req.user) === null || _a === void 0 ? void 0 : _a.role) === 'admin'; };
/**
 * Validates client-supplied history. Only "user" and "assistant" roles are
 * accepted — client-supplied "system" (or any other) instructions are rejected.
 */
const validateHistory = (raw) => {
    if (raw === undefined || raw === null)
        return { ok: true, history: [] };
    if (!Array.isArray(raw))
        return { ok: false, error: 'history must be an array of { role, content } messages.' };
    const recent = raw.slice(-MAX_HISTORY_ITEMS);
    for (const item of recent) {
        if (!item || typeof item !== 'object')
            return { ok: false, error: 'Each history item must be an object.' };
        const { role, content } = item;
        if (role !== 'user' && role !== 'assistant') {
            return { ok: false, error: 'history roles must be "user" or "assistant".' };
        }
        if (typeof content !== 'string')
            return { ok: false, error: 'history content must be a string.' };
    }
    return { ok: true, history: recent };
};
const aiStatus = (req, res) => {
    try {
        res.json({ success: true, status: (0, aiProviderService_1.getAIStatus)({ includeKeyDetails: isAdmin(req) }) });
    }
    catch (error) {
        console.error('[AIController] Status failed:', error instanceof Error ? error.message : 'unknown error');
        res.status(500).json({ success: false, error: 'Unable to read AI status.', code: 'AI_STATUS_UNAVAILABLE' });
    }
};
exports.aiStatus = aiStatus;
const chat = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b;
    const question = questionFrom(req);
    if (!question || question.length > MAX_QUESTION_CHARS) {
        res.status(400).json({ success: false, error: `A question between 1 and ${MAX_QUESTION_CHARS} characters is required.`, code: 'INVALID_QUESTION' });
        return;
    }
    const rawContext = (_a = req.body) === null || _a === void 0 ? void 0 : _a.context;
    if (rawContext !== undefined && (typeof rawContext !== 'string' || rawContext.length > MAX_CONTEXT_CHARS)) {
        res.status(400).json({ success: false, error: `context must be a string of at most ${MAX_CONTEXT_CHARS} characters.`, code: 'INVALID_CONTEXT' });
        return;
    }
    const historyCheck = validateHistory((_b = req.body) === null || _b === void 0 ? void 0 : _b.history);
    if (!historyCheck.ok) {
        res.status(400).json({ success: false, error: historyCheck.error, code: 'INVALID_HISTORY' });
        return;
    }
    try {
        const history = (0, aiOrchestrator_1.sanitizeHistory)(historyCheck.history, question);
        const result = yield (0, aiOrchestrator_1.answerQuestion)(question, typeof rawContext === 'string' ? rawContext : '', history);
        const actor = (0, auditService_1.getActorContext)(req);
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, actor), { action: 'ai_chat_question', category: 'system', source: 'ai-rakshak', requestId: (0, auditService_1.getRequestId)(req), 
            // No conversation content is stored — only how the answer was produced.
            metadata: { provider: result.provider, mode: result.mode, model: result.model, fallbackUsed: result.fallbackUsed } }));
        res.json(Object.assign({ success: true }, result));
    }
    catch (error) {
        console.error('[AIController] Chat request failed:', error instanceof Error ? error.message : 'unknown error');
        res.status(503).json({
            success: false,
            error: 'AI RAKSHAK encountered an unexpected error. Please try again.',
            code: 'AI_CHAT_UNAVAILABLE',
        });
    }
});
exports.chat = chat;
const explain = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _c;
    const finding = typeof ((_c = req.body) === null || _c === void 0 ? void 0 : _c.finding) === 'string' ? req.body.finding.trim() : '';
    if (!finding || finding.length > MAX_QUESTION_CHARS) {
        res.status(400).json({ success: false, error: 'A verified finding between 1 and 2000 characters is required.', code: 'INVALID_FINDING' });
        return;
    }
    try {
        const result = yield (0, aiOrchestrator_1.answerQuestion)(`Explain this verified security finding and provide safe next steps: ${finding}`, finding);
        res.json(Object.assign({ success: true }, result));
    }
    catch (error) {
        console.error('[AIController] Explain request failed:', error instanceof Error ? error.message : 'unknown error');
        res.status(503).json({ success: false, error: 'AI RAKSHAK could not explain this finding right now.', code: 'AI_EXPLAIN_UNAVAILABLE' });
    }
});
exports.explain = explain;
const recommendations = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const actor = (0, auditService_1.getActorContext)(req);
        const events = yield auditLog_model_1.default.find({ actorId: actor.actorId, severity: { $in: ['high', 'critical'] } })
            .sort({ timestamp: -1 })
            .limit(10)
            .lean();
        const items = events.map((event) => ({
            title: `Review ${event.action.replace(/_/g, ' ')}`,
            reason: `A ${event.severity} event was recorded by ${event.source}.`,
            priority: event.severity,
            suggestedAction: 'Open the related security service and follow its verified remediation guidance.',
            service: event.category,
            createdAt: event.timestamp,
        }));
        res.json({ success: true, recommendations: items });
    }
    catch (error) {
        console.error('[AIController] Recommendations failed:', error instanceof Error ? error.message : 'unknown error');
        res.status(500).json({ success: false, error: 'Unable to load recommendations.', code: 'AI_RECOMMENDATIONS_UNAVAILABLE' });
    }
});
exports.recommendations = recommendations;
/**
 * AI provider preference (admin only).
 * API keys are managed exclusively through backend environment variables and
 * can no longer be set or replaced over HTTP.
 */
const configureAI = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const actor = (0, auditService_1.getActorContext)(req);
    const requestId = (0, auditService_1.getRequestId)(req);
    if (!isAdmin(req)) {
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, actor), { action: 'ai_configuration_denied', category: 'administration', status: 'denied', severity: 'medium', source: 'ai-rakshak', requestId }));
        res.status(403).json({
            success: false,
            error: 'Only administrators can change the AI provider configuration.',
            code: 'ADMIN_REQUIRED',
        });
        return;
    }
    const { apiKey, preferredProvider } = req.body || {};
    if (apiKey !== undefined) {
        res.status(400).json({
            success: false,
            error: 'API keys are managed securely through server environment configuration and cannot be set from the browser.',
            code: 'API_KEYS_ENV_ONLY',
        });
        return;
    }
    if (typeof preferredProvider !== 'string' || !aiProviderService_1.PROVIDER_PREFERENCES.includes(preferredProvider)) {
        res.status(400).json({
            success: false,
            error: `preferredProvider must be one of: ${aiProviderService_1.PROVIDER_PREFERENCES.join(', ')}.`,
            code: 'INVALID_PROVIDER',
        });
        return;
    }
    try {
        (0, aiProviderService_1.setPreferredProvider)(preferredProvider);
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, actor), { action: 'ai_provider_preference_updated', category: 'administration', severity: 'low', source: 'ai-rakshak', requestId, metadata: { preferredProvider } }));
        res.json({
            success: true,
            message: `AI provider preference set to ${preferredProvider}.`,
            status: (0, aiProviderService_1.getAIStatus)({ includeKeyDetails: true }),
        });
    }
    catch (error) {
        console.error('[AIController] Configure failed:', error instanceof Error ? error.message : 'unknown error');
        res.status(500).json({ success: false, error: 'Unable to update AI configuration.', code: 'AI_CONFIGURE_FAILED' });
    }
});
exports.configureAI = configureAI;
