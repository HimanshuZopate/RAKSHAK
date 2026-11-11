import mongoose, { Document, Schema } from 'mongoose';

export type ThreatCategory = 'SQLi' | 'XSS' | 'Path Traversal' | 'Command Injection' | 'Suspicious' | 'None';
export type WafAction = 'Blocked' | 'Allowed';

export interface ITrafficLog extends Document {
  ipAddress: string;
  method: string;
  endpoint: string;
  payload: string;
  threatType: ThreatCategory;
  action: WafAction;
  statusCode: number;
  country: string;
  countryCode: string;
  city: string;
  userAgent?: string;
  ruleMatched?: string;
  timestamp: Date;
}

const TrafficLogSchema = new Schema<ITrafficLog>(
  {
    ipAddress: {
      type: String,
      required: true,
      index: true,
    },
    method: {
      type: String,
      required: true,
      uppercase: true,
    },
    endpoint: {
      type: String,
      required: true,
      index: true,
    },
    payload: {
      type: String,
      default: '',
    },
    threatType: {
      type: String,
      enum: ['SQLi', 'XSS', 'Path Traversal', 'Command Injection', 'Suspicious', 'None'],
      default: 'None',
      index: true,
    },
    action: {
      type: String,
      enum: ['Blocked', 'Allowed'],
      required: true,
      index: true,
    },
    statusCode: {
      type: Number,
      default: 200,
    },
    country: {
      type: String,
      default: 'Local / Private',
      index: true,
    },
    countryCode: {
      type: String,
      default: 'LOCAL',
    },
    city: {
      type: String,
      default: 'Internal Network',
    },
    userAgent: {
      type: String,
      default: '',
    },
    ruleMatched: {
      type: String,
      default: '',
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: false,
    versionKey: false,
  }
);

// Composite indexes for fast analytical aggregation
TrafficLogSchema.index({ timestamp: -1, threatType: 1 });
TrafficLogSchema.index({ action: 1, timestamp: -1 });

export const TrafficLogModel = mongoose.model<ITrafficLog>('TrafficLog', TrafficLogSchema);
export default TrafficLogModel;
