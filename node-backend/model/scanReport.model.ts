import mongoose, { Document, Schema } from 'mongoose';

export interface IFinding {
  type: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export type WebScanStatus = 'running' | 'completed' | 'cancelled' | 'failed' | 'timed_out';

export interface IScanReport extends Document {
  user: mongoose.Types.ObjectId;
  // Legacy socket-service scan fields (required for those documents only).
  target?: mongoose.Types.ObjectId;
  service: string;
  status?: 'Success' | 'Warning' | 'Failed';
  findings: IFinding[];
  createdAt: Date;

  // Web vulnerability assessment fields (kind === 'web-vulnerability').
  kind?: 'web-vulnerability';
  scanStatus?: WebScanStatus;
  targetUrl?: string;
  targetHost?: string;
  profile?: 'quick' | 'standard' | 'comprehensive';
  startedAt?: Date;
  completedAt?: Date;
  durationMs?: number;
  requestCount?: number;
  summary?: Record<string, unknown>;
  webFindings?: unknown[];
  checks?: unknown[];
  technologies?: unknown[];
  tls?: Record<string, unknown> | null;
  headerSnapshot?: Record<string, unknown> | null;
  limitations?: string[];
  scannerVersion?: string;
  errorMessage?: string | null;
}

const FindingSchema = new Schema<IFinding>({
  type: { type: String, required: true },
  description: { type: String, required: true },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
}, { _id: false });

function isLegacyReport(this: IScanReport) {
  return !this.kind;
}

const ScanReportSchema = new Schema<IScanReport>({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  target: { type: Schema.Types.ObjectId, ref: 'Target', required: isLegacyReport },
  service: { type: String, required: true },
  status: { type: String, enum: ['Success', 'Warning', 'Failed'], required: isLegacyReport },
  findings: { type: [FindingSchema], default: [] },
  createdAt: { type: Date, default: Date.now },

  kind: { type: String, enum: ['web-vulnerability'] },
  scanStatus: { type: String, enum: ['running', 'completed', 'cancelled', 'failed', 'timed_out'] },
  targetUrl: { type: String, maxlength: 2048 },
  targetHost: { type: String, maxlength: 255 },
  profile: { type: String, enum: ['quick', 'standard', 'comprehensive'] },
  startedAt: { type: Date },
  completedAt: { type: Date },
  durationMs: { type: Number },
  requestCount: { type: Number },
  summary: { type: Schema.Types.Mixed },
  webFindings: { type: [Schema.Types.Mixed], default: undefined },
  checks: { type: [Schema.Types.Mixed], default: undefined },
  technologies: { type: [Schema.Types.Mixed], default: undefined },
  tls: { type: Schema.Types.Mixed },
  headerSnapshot: { type: Schema.Types.Mixed },
  limitations: { type: [String], default: undefined },
  scannerVersion: { type: String },
  errorMessage: { type: String },
});

// Scan-history queries: "my web scans, newest first".
ScanReportSchema.index({ user: 1, kind: 1, createdAt: -1 });

export const ScanReportModel = mongoose.model<IScanReport>('ScanReport', ScanReportSchema);
