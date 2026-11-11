"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.emailLimiter = exports.apiLimiter = exports.authLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
/**
 * Strict rate limiter for Authentication endpoints (Login, Register, Password Reset)
 * Mitigates credential stuffing, password brute-forcing, and email flooding.
 */
exports.authLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many authentication attempts. Please try again after 15 minutes.',
        code: 'RATE_LIMIT_EXCEEDED',
    },
    skipSuccessfulRequests: false,
});
/**
 * Moderate rate limiter for general API routes
 */
exports.apiLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests. Please slow down.',
        code: 'RATE_LIMIT_EXCEEDED',
    },
});
/**
 * Resend email verification limiter to prevent inbox harassment
 */
exports.emailLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many email requests sent. Please try again later.',
        code: 'EMAIL_RATE_LIMIT_EXCEEDED',
    },
});
