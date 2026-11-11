import { Schema, model, Document } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

export type AuditCategory =
  | 'authentication'
  | 'security scan'
  | 'phishing'
  | 'simulation'
  | 'administration'
  | 'system';

export type AuditStatus = 'success' | 'failure' | 'denied' | 'partial';
export type AuditSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type AuditActorType = 'system' | 'anonymous' | 'user' | 'admin';

export interface IAuditLog extends Document {
  eventId: string;
  timestamp: Date;
  actorId?: string;
  actorType: AuditActorType;
  action: string;
  category: AuditCategory | string;
  resourceType?: string;
  resourceId?: string;
  status: AuditStatus;
  severity: AuditSeverity;
  source: string;
  requestId?: string;
  metadata?: Record<string, any>;
  errorCode?: string;
  createdAt: Date;
  updatedAt: Date;
}

const AuditLogSchema = new Schema<IAuditLog>(
  {
    eventId: {
      type: String,
      required: true,
      unique: true,
      default: () => uuidv4(),
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
      type: Schema.Types.Mixed,
      default: {},
    },
    errorCode: {
      type: String,
      default: null,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ category: 1, status: 1, timestamp: -1 });

const AuditLogModel = model<IAuditLog>('AuditLog', AuditLogSchema);

export default AuditLogModel;
