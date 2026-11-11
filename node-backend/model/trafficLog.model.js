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
exports.TrafficLogModel = void 0;
const mongoose_1 = __importStar(require("mongoose"));
const TrafficLogSchema = new mongoose_1.Schema({
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
}, {
    timestamps: false,
    versionKey: false,
});
// Composite indexes for fast analytical aggregation
TrafficLogSchema.index({ timestamp: -1, threatType: 1 });
TrafficLogSchema.index({ action: 1, timestamp: -1 });
exports.TrafficLogModel = mongoose_1.default.model('TrafficLog', TrafficLogSchema);
exports.default = exports.TrafficLogModel;
