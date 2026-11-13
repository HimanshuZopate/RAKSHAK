"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScanReportModel = void 0;
const mongoose_1 = __importStar(require("mongoose"));
const FindingSchema = new mongoose_1.Schema({
    type: { type: String, required: true },
    description: { type: String, required: true },
    severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
}, { _id: false });
function isLegacyReport() {
    return !this.kind;
}
const ScanReportSchema = new mongoose_1.Schema({
    user: { type: mongoose_1.Schema.Types.ObjectId, ref: 'User', required: true },
    target: { type: mongoose_1.Schema.Types.ObjectId, ref: 'Target', required: isLegacyReport },
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
    summary: { type: mongoose_1.Schema.Types.Mixed },
    webFindings: { type: [mongoose_1.Schema.Types.Mixed], default: undefined },
    checks: { type: [mongoose_1.Schema.Types.Mixed], default: undefined },
    technologies: { type: [mongoose_1.Schema.Types.Mixed], default: undefined },
    tls: { type: mongoose_1.Schema.Types.Mixed },
    headerSnapshot: { type: mongoose_1.Schema.Types.Mixed },
    limitations: { type: [String], default: undefined },
    scannerVersion: { type: String },
    errorMessage: { type: String },
});
// Scan-history queries: "my web scans, newest first".
ScanReportSchema.index({ user: 1, kind: 1, createdAt: -1 });
exports.ScanReportModel = mongoose_1.default.model('ScanReport', ScanReportSchema);
