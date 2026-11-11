import mongoose, { Document, Schema } from 'mongoose';

export interface ITechStack {
  name: string;
  version: string;
}

export interface ITarget extends Document {
  user: mongoose.Types.ObjectId;
  name: string;
  host: string;
  environment: 'Production' | 'Staging' | 'Dev';
  techStack: ITechStack[];
  createdAt: Date;
}

const TechStackSchema = new Schema<ITechStack>({
  name: { type: String, required: true },
  version: { type: String, required: true },
}, { _id: false });

const TargetSchema = new Schema<ITarget>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  host: {
    type: String,
    required: true,
    trim: true,
  },
  environment: {
    type: String,
    enum: ['Production', 'Staging', 'Dev'],
    required: true,
  },
  techStack: {
    type: [TechStackSchema],
    default: [],
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export const TargetModel = mongoose.model<ITarget>('Target', TargetSchema);
