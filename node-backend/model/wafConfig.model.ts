import mongoose, { Document, Schema } from 'mongoose';

export type WafMode = 'active' | 'simulation';

export interface IWafConfig extends Document {
  mode: WafMode;
  sqlInjection: boolean;
  xss: boolean;
  pathTraversal: boolean;
  commandInjection: boolean;
  blockLocalTraffic: boolean;
  updatedAt: Date;
}

const WafConfigSchema = new Schema<IWafConfig>(
  {
    mode: {
      type: String,
      enum: ['active', 'simulation'],
      default: 'active',
      required: true,
    },
    sqlInjection: {
      type: Boolean,
      default: true,
    },
    xss: {
      type: Boolean,
      default: true,
    },
    pathTraversal: {
      type: Boolean,
      default: true,
    },
    commandInjection: {
      type: Boolean,
      default: true,
    },
    blockLocalTraffic: {
      type: Boolean,
      default: true,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    versionKey: false,
  }
);

export const WafConfigModel = mongoose.model<IWafConfig>('WafConfig', WafConfigSchema);
export default WafConfigModel;
