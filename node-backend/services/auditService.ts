import { Request } from 'express';
import { v4 as uuidv4 } from 'uuid';
import AuditLogModel, { AuditCategory, AuditSeverity, AuditStatus, AuditActorType } from '../model/auditLog.model';

const MAX_STRING_LEN = 255;
const MAX_ARRAY_ITEMS = 10;
const MAX_DEPTH = 3;
const SENSITIVE_KEYS = /(password|passphrase|secret|token|cookie|authorization|api[_-]?key|otp|session|jwt|credential)/i;

export type AuditRecordInput = {
  eventId?: string;
  actorId?: string;
  actorType?: AuditActorType;
  action: string;
  category?: AuditCategory | string;
  resourceType?: string;
  resourceId?: string;
  status?: AuditStatus;
  severity?: AuditSeverity;
  source?: string;
  requestId?: string;
  metadata?: Record<string, any>;
  errorCode?: string;
  timestamp?: Date | string;
};

const clampString = (value: string): string => {
  const trimmed = value.trim().replace(/\s+/g, ' ');
  return trimmed.length > MAX_STRING_LEN ? `${trimmed.slice(0, MAX_STRING_LEN - 3)}...` : trimmed;
};

const sanitizeMetadataValue = (value: any, depth = 0): any => {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') return clampString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    if (depth >= MAX_DEPTH) return undefined;
    const items = value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeMetadataValue(item, depth + 1))
      .filter((item) => item !== undefined);
    return items.length ? items : undefined;
  }
  if (typeof value === 'object') {
    if (depth >= MAX_DEPTH) return undefined;
    const output: Record<string, any> = {};
    for (const [key, rawValue] of Object.entries(value)) {
      if (SENSITIVE_KEYS.test(key)) continue;
      const sanitized = sanitizeMetadataValue(rawValue, depth + 1);
      if (sanitized !== undefined) output[key] = sanitized;
      if (Object.keys(output).length >= 12) break;
    }
    return Object.keys(output).length ? output : undefined;
  }
  return undefined;
};

export const sanitizeMetadata = (metadata?: Record<string, any>): Record<string, any> => {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return {};
  }

  const sanitized = sanitizeMetadataValue(metadata, 0);
  return sanitized && typeof sanitized === 'object' && !Array.isArray(sanitized) ? sanitized : {};
};

export const getRequestId = (req?: Pick<Request, 'headers'>): string | undefined => {
  const headerValue = req?.headers['x-request-id'] || req?.headers['x-correlation-id'];
  if (Array.isArray(headerValue)) return headerValue[0];
  return typeof headerValue === 'string' ? headerValue : undefined;
};

export const getActorContext = (req?: Pick<Request, 'user'>): { actorId: string; actorType: AuditActorType } => {
  const user = req?.user as any;
  if (!user || (!user.userId && !user._id && !user.id)) {
    return {
      actorId: 'system',
      actorType: 'system',
    };
  }

  const actorId = String(user.userId || user._id || user.id);
  return {
    actorId,
    actorType: user.role === 'admin' ? 'admin' : 'user',
  };
};

export const safeUrlPreview = (rawUrl?: string): string | undefined => {
  if (!rawUrl || typeof rawUrl !== 'string') return undefined;
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.host || parsed.hostname;
    if (!host) return undefined;
    return `${parsed.protocol}//${host}${parsed.pathname ? parsed.pathname.slice(0, 80) : ''}`;
  } catch {
    const trimmed = rawUrl.trim().replace(/\s+/g, ' ');
    if (!trimmed) return undefined;
    const withoutCredentials = trimmed.replace(/\/\/([^@]+)@/i, '//[redacted]@');
    return withoutCredentials.length > MAX_STRING_LEN
      ? `${withoutCredentials.slice(0, MAX_STRING_LEN - 3)}...`
      : withoutCredentials;
  }
};

export const recordAuditEvent = async (event: AuditRecordInput): Promise<boolean> => {
  if (!event?.action) {
    return false;
  }

  const safeAction = clampString(event.action);
  const normalized: Record<string, any> = {
    eventId: event.eventId || uuidv4(),
    timestamp: event.timestamp ? new Date(event.timestamp) : new Date(),
    actorId: event.actorId || 'system',
    actorType: event.actorType || 'system',
    action: safeAction,
    category: event.category || 'system',
    resourceType: event.resourceType || 'application',
    resourceId: event.resourceId || undefined,
    status: event.status || 'success',
    severity: event.severity || 'informational',
    source: event.source || 'application',
    requestId: event.requestId || undefined,
    metadata: sanitizeMetadata(event.metadata),
    errorCode: event.errorCode || undefined,
  };

  try {
    await AuditLogModel.create(normalized);
    return true;
  } catch (error) {
    console.error('[AuditService] Failed to write audit record:', error);
    return false;
  }
};
