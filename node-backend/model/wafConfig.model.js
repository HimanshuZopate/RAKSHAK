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
exports.WafConfigModel = void 0;
const mongoose_1 = __importStar(require("mongoose"));
const WafConfigSchema = new mongoose_1.Schema({
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
}, {
    versionKey: false,
});
exports.WafConfigModel = mongoose_1.default.model('WafConfig', WafConfigSchema);
exports.default = exports.WafConfigModel;
