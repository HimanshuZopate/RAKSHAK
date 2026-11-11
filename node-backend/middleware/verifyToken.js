"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.optionalVerifyToken = exports.verifyToken = void 0;
const jwt_util_1 = require("../util/jwt.util");
/**
 * JWT Verification Middleware
 * Reads Access Token strictly from HttpOnly cookie (or Bearer Authorization header fallback)
 */
const verifyToken = (req, res, next) => {
    var _a, _b;
    try {
        // 1. Primary location: HttpOnly cookie
        let token = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.accessToken;
        // 2. Fallback: Bearer Authorization header for headless API clients
        if (!token && ((_b = req.headers.authorization) === null || _b === void 0 ? void 0 : _b.startsWith('Bearer '))) {
            token = req.headers.authorization.split(' ')[1];
        }
        if (!token) {
            return res.status(401).json({
                error: 'Authentication required. No access token provided.',
                code: 'NO_TOKEN',
            });
        }
        // 3. Verify token signature and expiration
        const decoded = (0, jwt_util_1.verifyAccessToken)(token);
        req.user = decoded;
        return next();
    }
    catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Access token expired. Please refresh session.',
                code: 'TOKEN_EXPIRED',
            });
        }
        return res.status(401).json({
            error: 'Invalid access token.',
            code: 'TOKEN_INVALID',
        });
    }
};
exports.verifyToken = verifyToken;
/**
 * Optional JWT Verification Middleware
 * Attaches user payload if a valid token is present, but permits anonymous requests
 */
const optionalVerifyToken = (req, _res, next) => {
    var _a, _b;
    try {
        let token = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.accessToken;
        if (!token && ((_b = req.headers.authorization) === null || _b === void 0 ? void 0 : _b.startsWith('Bearer '))) {
            token = req.headers.authorization.split(' ')[1];
        }
        if (token) {
            const decoded = (0, jwt_util_1.verifyAccessToken)(token);
            req.user = decoded;
        }
    }
    catch (_c) {
        // Continue anonymously without blocking
    }
    return next();
};
exports.optionalVerifyToken = optionalVerifyToken;
