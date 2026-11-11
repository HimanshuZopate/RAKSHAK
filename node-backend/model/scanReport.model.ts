import mongoose, { Document, Schema } from 'mongoose';

export interface IFinding {
  type: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface IScanReport extends Document {
  user: mongoose.Types.ObjectId;
  target: mongoose.Types.ObjectId;
  service: string;
  status: 'Success' | 'Warning' | 'Failed';
  findings: IFinding[];
  createdAt: Date;
}

const FindingSchema = new Schema<IFinding>({
  type: { type: String, required: true },
  description: { type: String, required: true },
  severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
}, { _id: false });

const ScanReportSchema = new Schema<IScanReport>({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  target: { type: Schema.Types.ObjectId, ref: 'Target', required: true },
  service: { type: String, required: true },
  status: { type: String, enum: ['Success', 'Warning', 'Failed'], required: true },
  findings: { type: [FindingSchema], default: [] },
  createdAt: { type: Date, default: Date.now },
});

export const ScanReportModel = mongoose.model<IScanReport>('ScanReport', ScanReportSchema);
