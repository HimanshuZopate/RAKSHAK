"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mongoose_1 = require("mongoose");
const uuid_1 = require("uuid");
const AuditLogSchema = new mongoose_1.Schema({
    eventId: {
        type: String,
        required: true,
        unique: true,
        default: () => (0, uuid_1.v4)(),
        index: true,
    },
    timestamp: {
        type: Date,
        required: true,
        default: Date.now,
        index: true,
    },
    actorId: {
        type: String,
        default: 'system',
        index: true,
    },
    actorType: {
        type: String,
        enum: ['system', 'anonymous', 'user', 'admin'],
        default: 'system',
        index: true,
    },
    action: {
        type: String,
        required: true,
        index: true,
        trim: true,
    },
    category: {
        type: String,
        required: true,
        enum: ['authentication', 'security scan', 'phishing', 'simulation', 'administration', 'system'],
        default: 'system',
        index: true,
    },
    resourceType: {
        type: String,
        default: 'application',
        index: true,
    },
    resourceId: {
        type: String,
        default: null,
        index: true,
    },
    status: {
        type: String,
        enum: ['success', 'failure', 'denied', 'partial'],
        default: 'success',
        index: true,
    },
    severity: {
        type: String,
        enum: ['informational', 'low', 'medium', 'high', 'critical'],
        default: 'informational',
        index: true,
    },
    source: {
        type: String,
        required: true,
        default: 'application',
        index: true,
    },
    requestId: {
        type: String,
        default: null,
        index: true,
    },
    metadata: {
        type: mongoose_1.Schema.Types.Mixed,
        default: {},
    },
    errorCode: {
        type: String,
        default: null,
        index: true,
    },
}, {
    timestamps: true,
});
AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ category: 1, status: 1, timestamp: -1 });
const AuditLogModel = (0, mongoose_1.model)('AuditLog', AuditLogSchema);
exports.default = AuditLogModel;
