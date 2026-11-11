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
exports.recordAuditEvent = exports.safeUrlPreview = exports.getActorContext = exports.getRequestId = exports.sanitizeMetadata = void 0;
const uuid_1 = require("uuid");
const auditLog_model_1 = __importDefault(require("../model/auditLog.model"));
const MAX_STRING_LEN = 255;
const MAX_ARRAY_ITEMS = 10;
const MAX_DEPTH = 3;
const SENSITIVE_KEYS = /(password|passphrase|secret|token|cookie|authorization|api[_-]?key|otp|session|jwt|credential)/i;
const clampString = (value) => {
    const trimmed = value.trim().replace(/\s+/g, ' ');
    return trimmed.length > MAX_STRING_LEN ? `${trimmed.slice(0, MAX_STRING_LEN - 3)}...` : trimmed;
};
const sanitizeMetadataValue = (value, depth = 0) => {
    if (value === null || value === undefined)
        return undefined;
    if (typeof value === 'string')
        return clampString(value);
    if (typeof value === 'number' || typeof value === 'boolean')
        return value;
    if (Array.isArray(value)) {
        if (depth >= MAX_DEPTH)
            return undefined;
        const items = value
            .slice(0, MAX_ARRAY_ITEMS)
            .map((item) => sanitizeMetadataValue(item, depth + 1))
            .filter((item) => item !== undefined);
        return items.length ? items : undefined;
    }
    if (typeof value === 'object') {
        if (depth >= MAX_DEPTH)
            return undefined;
        const output = {};
        for (const [key, rawValue] of Object.entries(value)) {
            if (SENSITIVE_KEYS.test(key))
                continue;
            const sanitized = sanitizeMetadataValue(rawValue, depth + 1);
            if (sanitized !== undefined)
                output[key] = sanitized;
            if (Object.keys(output).length >= 12)
                break;
        }
        return Object.keys(output).length ? output : undefined;
    }
    return undefined;
};
const sanitizeMetadata = (metadata) => {
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
        return {};
    }
    const sanitized = sanitizeMetadataValue(metadata, 0);
    return sanitized && typeof sanitized === 'object' && !Array.isArray(sanitized) ? sanitized : {};
};
exports.sanitizeMetadata = sanitizeMetadata;
const getRequestId = (req) => {
    const headerValue = (req === null || req === void 0 ? void 0 : req.headers['x-request-id']) || (req === null || req === void 0 ? void 0 : req.headers['x-correlation-id']);
    if (Array.isArray(headerValue))
        return headerValue[0];
    return typeof headerValue === 'string' ? headerValue : undefined;
};
exports.getRequestId = getRequestId;
const getActorContext = (req) => {
    const user = req === null || req === void 0 ? void 0 : req.user;
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
exports.getActorContext = getActorContext;
const safeUrlPreview = (rawUrl) => {
    if (!rawUrl || typeof rawUrl !== 'string')
        return undefined;
    try {
        const parsed = new URL(rawUrl);
        const host = parsed.host || parsed.hostname;
        if (!host)
            return undefined;
        return `${parsed.protocol}//${host}${parsed.pathname ? parsed.pathname.slice(0, 80) : ''}`;
    }
    catch (_a) {
        const trimmed = rawUrl.trim().replace(/\s+/g, ' ');
        if (!trimmed)
            return undefined;
        const withoutCredentials = trimmed.replace(/\/\/([^@]+)@/i, '//[redacted]@');
        return withoutCredentials.length > MAX_STRING_LEN
            ? `${withoutCredentials.slice(0, MAX_STRING_LEN - 3)}...`
            : withoutCredentials;
    }
};
exports.safeUrlPreview = safeUrlPreview;
const recordAuditEvent = (event) => __awaiter(void 0, void 0, void 0, function* () {
    if (!(event === null || event === void 0 ? void 0 : event.action)) {
        return false;
    }
    const safeAction = clampString(event.action);
    const normalized = {
        eventId: event.eventId || (0, uuid_1.v4)(),
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
        metadata: (0, exports.sanitizeMetadata)(event.metadata),
        errorCode: event.errorCode || undefined,
    };
    try {
        yield auditLog_model_1.default.create(normalized);
        return true;
    }
    catch (error) {
        console.error('[AuditService] Failed to write audit record:', error);
        return false;
    }
});
exports.recordAuditEvent = recordAuditEvent;
