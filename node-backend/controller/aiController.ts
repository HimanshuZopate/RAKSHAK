import { Request, Response } from 'express';
import { answerQuestion, sanitizeHistory } from '../services/aiOrchestrator';
import {
  getAIStatus,
  setPreferredProvider,
  PROVIDER_PREFERENCES,
  ProviderPreference,
} from '../services/aiProviderService';
import { getActorContext, getRequestId, recordAuditEvent } from '../services/auditService';
import AuditLogModel from '../model/auditLog.model';

const MAX_QUESTION_CHARS = 2000;
const MAX_CONTEXT_CHARS = 4000;
const MAX_HISTORY_ITEMS = 50;

const questionFrom = (req: Request): string =>
  typeof req.body?.question === 'string' ? req.body.question.trim() : '';

const isAdmin = (req: Request): boolean => req.user?.role === 'admin';

/**
 * Validates client-supplied history. Only "user" and "assistant" roles are
 * accepted — client-supplied "system" (or any other) instructions are rejected.
 */
const validateHistory = (raw: unknown): { ok: true; history: unknown[] } | { ok: false; error: string } => {
  if (raw === undefined || raw === null) return { ok: true, history: [] };
  if (!Array.isArray(raw)) return { ok: false, error: 'history must be an array of { role, content } messages.' };
  const recent = raw.slice(-MAX_HISTORY_ITEMS);
  for (const item of recent) {
    if (!item || typeof item !== 'object') return { ok: false, error: 'Each history item must be an object.' };
    const { role, content } = item as { role?: unknown; content?: unknown };
    if (role !== 'user' && role !== 'assistant') {
      return { ok: false, error: 'history roles must be "user" or "assistant".' };
    }
    if (typeof content !== 'string') return { ok: false, error: 'history content must be a string.' };
  }
  return { ok: true, history: recent };
};

export const aiStatus = (req: Request, res: Response): void => {
  try {
    res.json({ success: true, status: getAIStatus({ includeKeyDetails: isAdmin(req) }) });
  } catch (error) {
    console.error('[AIController] Status failed:', error instanceof Error ? error.message : 'unknown error');
    res.status(500).json({ success: false, error: 'Unable to read AI status.', code: 'AI_STATUS_UNAVAILABLE' });
  }
};

export const chat = async (req: Request, res: Response): Promise<void> => {
  const question = questionFrom(req);
  if (!question || question.length > MAX_QUESTION_CHARS) {
    res.status(400).json({ success: false, error: `A question between 1 and ${MAX_QUESTION_CHARS} characters is required.`, code: 'INVALID_QUESTION' });
    return;
  }

  const rawContext = req.body?.context;
  if (rawContext !== undefined && (typeof rawContext !== 'string' || rawContext.length > MAX_CONTEXT_CHARS)) {
    res.status(400).json({ success: false, error: `context must be a string of at most ${MAX_CONTEXT_CHARS} characters.`, code: 'INVALID_CONTEXT' });
    return;
  }

  const historyCheck = validateHistory(req.body?.history);
  if (!historyCheck.ok) {
    res.status(400).json({ success: false, error: historyCheck.error, code: 'INVALID_HISTORY' });
    return;
  }

  try {
    const history = sanitizeHistory(historyCheck.history, question);
    const result = await answerQuestion(question, typeof rawContext === 'string' ? rawContext : '', history);
    const actor = getActorContext(req);

    await recordAuditEvent({
      ...actor,
      action: 'ai_chat_question',
      category: 'system',
      source: 'ai-rakshak',
      requestId: getRequestId(req),
      // No conversation content is stored — only how the answer was produced.
      metadata: { provider: result.provider, mode: result.mode, model: result.model, fallbackUsed: result.fallbackUsed },
    });

    res.json({ success: true, ...result });
  } catch (error) {
    console.error('[AIController] Chat request failed:', error instanceof Error ? error.message : 'unknown error');
    res.status(503).json({
      success: false,
      error: 'AI RAKSHAK encountered an unexpected error. Please try again.',
      code: 'AI_CHAT_UNAVAILABLE',
    });
  }
};

export const explain = async (req: Request, res: Response): Promise<void> => {
  const finding = typeof req.body?.finding === 'string' ? req.body.finding.trim() : '';
  if (!finding || finding.length > MAX_QUESTION_CHARS) {
    res.status(400).json({ success: false, error: 'A verified finding between 1 and 2000 characters is required.', code: 'INVALID_FINDING' });
    return;
  }
  try {
    const result = await answerQuestion(`Explain this verified security finding and provide safe next steps: ${finding}`, finding);
    res.json({ success: true, ...result });
  } catch (error) {
    console.error('[AIController] Explain request failed:', error instanceof Error ? error.message : 'unknown error');
    res.status(503).json({ success: false, error: 'AI RAKSHAK could not explain this finding right now.', code: 'AI_EXPLAIN_UNAVAILABLE' });
  }
};

export const recommendations = async (req: Request, res: Response): Promise<void> => {
  try {
    const actor = getActorContext(req);
    const events = await AuditLogModel.find({ actorId: actor.actorId, severity: { $in: ['high', 'critical'] } })
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
  } catch (error) {
    console.error('[AIController] Recommendations failed:', error instanceof Error ? error.message : 'unknown error');
    res.status(500).json({ success: false, error: 'Unable to load recommendations.', code: 'AI_RECOMMENDATIONS_UNAVAILABLE' });
  }
};

/**
 * AI provider preference (admin only).
 * API keys are managed exclusively through backend environment variables and
 * can no longer be set or replaced over HTTP.
 */
export const configureAI = async (req: Request, res: Response): Promise<void> => {
  const actor = getActorContext(req);
  const requestId = getRequestId(req);

  if (!isAdmin(req)) {
    await recordAuditEvent({
      ...actor,
      action: 'ai_configuration_denied',
      category: 'administration',
      status: 'denied',
      severity: 'medium',
      source: 'ai-rakshak',
      requestId,
    });
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

  if (typeof preferredProvider !== 'string' || !PROVIDER_PREFERENCES.includes(preferredProvider as ProviderPreference)) {
    res.status(400).json({
      success: false,
      error: `preferredProvider must be one of: ${PROVIDER_PREFERENCES.join(', ')}.`,
      code: 'INVALID_PROVIDER',
    });
    return;
  }

  try {
    setPreferredProvider(preferredProvider as ProviderPreference);
    await recordAuditEvent({
      ...actor,
      action: 'ai_provider_preference_updated',
      category: 'administration',
      severity: 'low',
      source: 'ai-rakshak',
      requestId,
      metadata: { preferredProvider },
    });
    res.json({
      success: true,
      message: `AI provider preference set to ${preferredProvider}.`,
      status: getAIStatus({ includeKeyDetails: true }),
    });
  } catch (error) {
    console.error('[AIController] Configure failed:', error instanceof Error ? error.message : 'unknown error');
    res.status(500).json({ success: false, error: 'Unable to update AI configuration.', code: 'AI_CONFIGURE_FAILED' });
  }
};
