"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateResetToken = void 0;
const crypto_1 = __importDefault(require("crypto"));
const generateResetToken = () => {
    const token = crypto_1.default.randomBytes(32).toString('hex');
    return token;
};
exports.generateResetToken = generateResetToken;
