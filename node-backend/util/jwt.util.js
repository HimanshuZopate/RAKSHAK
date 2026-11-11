"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.clearAuthCookies = exports.setAuthCookies = exports.verifyRefreshToken = exports.verifyAccessToken = exports.generateRefreshToken = exports.generateAccessToken = exports.getBaseCookieOptions = exports.REFRESH_COOKIE_MAX_AGE = exports.ACCESS_COOKIE_MAX_AGE = exports.getRefreshTokenSecret = exports.getAccessTokenSecret = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const getAccessTokenSecret = () => process.env.ACCESS_TOKEN_SECRET || 'dev_fallback_access_secret_key_123456789!@#';
exports.getAccessTokenSecret = getAccessTokenSecret;
const getRefreshTokenSecret = () => process.env.REFRESH_TOKEN_SECRET || 'dev_fallback_refresh_secret_key_987654321!@#';
exports.getRefreshTokenSecret = getRefreshTokenSecret;
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
exports.ACCESS_COOKIE_MAX_AGE = 15 * 60 * 1000; // 15 mins in ms
exports.REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days in ms
/**
 * Standard secure cookie options conforming to OWASP guidelines
 */
const getBaseCookieOptions = () => {
    const isProduction = process.env.NODE_ENV === 'production';
    return {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        path: '/',
    };
};
exports.getBaseCookieOptions = getBaseCookieOptions;
/**
 * Generate short-lived Access Token (15m default)
 */
const generateAccessToken = (payload) => {
    const options = {
        expiresIn: (process.env.ACCESS_TOKEN_EXPIRY || ACCESS_TOKEN_EXPIRY),
    };
    return jsonwebtoken_1.default.sign(payload, (0, exports.getAccessTokenSecret)(), options);
};
exports.generateAccessToken = generateAccessToken;
/**
 * Generate long-lived Refresh Token (7d default)
 */
const generateRefreshToken = (userId) => {
    const options = {
        expiresIn: (process.env.REFRESH_TOKEN_EXPIRY || REFRESH_TOKEN_EXPIRY),
    };
    return jsonwebtoken_1.default.sign({ userId }, (0, exports.getRefreshTokenSecret)(), options);
};
exports.generateRefreshToken = generateRefreshToken;
/**
 * Verify Access Token
 */
const verifyAccessToken = (token) => {
    return jsonwebtoken_1.default.verify(token, (0, exports.getAccessTokenSecret)());
};
exports.verifyAccessToken = verifyAccessToken;
/**
 * Verify Refresh Token
 */
const verifyRefreshToken = (token) => {
    return jsonwebtoken_1.default.verify(token, (0, exports.getRefreshTokenSecret)());
};
exports.verifyRefreshToken = verifyRefreshToken;
/**
 * Set HttpOnly, Secure, SameSite=Strict cookies on Express Response
 */
const setAuthCookies = (res, accessToken, refreshToken) => {
    const baseOptions = (0, exports.getBaseCookieOptions)();
    res.cookie('accessToken', accessToken, Object.assign(Object.assign({}, baseOptions), { maxAge: exports.ACCESS_COOKIE_MAX_AGE }));
    res.cookie('refreshToken', refreshToken, Object.assign(Object.assign({}, baseOptions), { maxAge: exports.REFRESH_COOKIE_MAX_AGE }));
};
exports.setAuthCookies = setAuthCookies;
/**
 * Clear authentication cookies on logout or invalid session
 */
const clearAuthCookies = (res) => {
    const baseOptions = (0, exports.getBaseCookieOptions)();
    res.clearCookie('accessToken', baseOptions);
    res.clearCookie('refreshToken', baseOptions);
};
exports.clearAuthCookies = clearAuthCookies;
