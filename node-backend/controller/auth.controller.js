"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetPassword = exports.verifyOtp = exports.updateProfile = exports.getCurrentUser = exports.logout = exports.refreshTokenController = exports.login = exports.resendVerificationEmail = exports.verifyEmail = exports.register = void 0;
const user_model_1 = __importDefault(require("../model/user.model"));
const resetToken_model_1 = __importDefault(require("../model/resetToken.model"));
const jwt_util_1 = require("../util/jwt.util");
const email_util_1 = require("../util/email.util");
const auditService_1 = require("../services/auditService");
/**
 * Strong password validator following OWASP guidance:
 * - At least 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one digit
 * - At least one special symbol
 */
const validatePasswordStrength = (password) => {
    if (password.length < 8) {
        return { valid: false, message: 'Password must be at least 8 characters long.' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one uppercase letter.' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one lowercase letter.' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one number.' };
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        return { valid: false, message: 'Password must contain at least one special character.' };
    }
    return { valid: true };
};
const logAuthEvent = (req, event) => __awaiter(void 0, void 0, void 0, function* () {
    yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({}, event), { category: 'authentication', source: 'auth', requestId: (0, auditService_1.getRequestId)(req), metadata: event.metadata || {} }));
});
/**
 * Register Controller
 * Validates inputs, creates a local account, and starts an authenticated session.
 */
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            yield logAuthEvent(req, {
                action: 'account_registration_rejected',
                status: 'denied',
                severity: 'low',
                metadata: { reason: 'missing_email_or_password' },
                errorCode: 'MISSING_CREDENTIALS',
            });
            return res.status(400).json({ error: 'Email and password are required.' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            yield logAuthEvent(req, {
                action: 'account_registration_rejected',
                status: 'denied',
                severity: 'low',
                metadata: { email: typeof email === 'string' ? email.slice(0, 64) : undefined },
                errorCode: 'INVALID_EMAIL_FORMAT',
            });
            return res.status(400).json({ error: 'Invalid email address format.' });
        }
        const passwordCheck = validatePasswordStrength(password);
        if (!passwordCheck.valid) {
            yield logAuthEvent(req, {
                action: 'account_registration_rejected',
                status: 'denied',
                severity: 'medium',
                metadata: { email: typeof email === 'string' ? email.slice(0, 64) : undefined },
                errorCode: 'WEAK_PASSWORD',
            });
            return res.status(400).json({ error: passwordCheck.message });
        }
        const existingUser = yield user_model_1.default.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) {
            yield logAuthEvent(req, {
                action: 'account_registration_rejected',
                status: 'denied',
                severity: 'low',
                metadata: { email: email.toLowerCase().trim().slice(0, 64) },
                errorCode: 'USER_ALREADY_EXISTS',
            });
            return res.status(400).json({
                error: 'An account with this email address already exists.',
            });
        }
        const newUser = new user_model_1.default({
            email: email.toLowerCase().trim(),
            password,
            isEmailVerified: true,
        });
        yield newUser.save();
        const accessToken = (0, jwt_util_1.generateAccessToken)({
            userId: newUser._id.toString(),
            email: newUser.email,
            role: newUser.role,
        });
        const refreshToken = (0, jwt_util_1.generateRefreshToken)(newUser._id.toString());
        newUser.refreshToken = refreshToken;
        yield newUser.save();
        yield logAuthEvent(req, {
            action: 'account_registration_successful',
            status: 'success',
            severity: 'low',
            actorId: newUser._id.toString(),
            actorType: 'user',
            resourceType: 'account',
            resourceId: newUser._id.toString(),
            metadata: { email: newUser.email },
        });
        (0, jwt_util_1.setAuthCookies)(res, accessToken, refreshToken);
        return res.status(201).json({
            message: 'Registration successful. You are now signed in.',
            email: newUser.email,
            user: newUser.toSafeUser(),
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ error: 'Server error during registration.' });
    }
});
exports.register = register;
/**
 * Verify Email Controller
 * Validates verification token and activates the account.
 */
const verifyEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const token = req.query.token || req.body.token;
        if (!token) {
            return res.status(400).json({ error: 'Verification token is required.' });
        }
        const user = yield user_model_1.default.findOne({
            verificationToken: token,
            verificationTokenExpires: { $gt: new Date() },
        }).select('+verificationToken +verificationTokenExpires');
        if (!user) {
            return res.status(400).json({
                error: 'Invalid or expired verification token.',
                code: 'TOKEN_INVALID_OR_EXPIRED',
            });
        }
        user.isEmailVerified = true;
        user.verificationToken = null;
        user.verificationTokenExpires = null;
        yield logAuthEvent(req, {
            action: 'email_verification_successful',
            status: 'success',
            severity: 'low',
            actorId: user._id.toString(),
            actorType: user.role === 'admin' ? 'admin' : 'user',
            resourceType: 'account',
            resourceId: user._id.toString(),
            metadata: { email: user.email },
        });
        // Issue tokens immediately upon verification
        const accessToken = (0, jwt_util_1.generateAccessToken)({
            userId: user._id.toString(),
            email: user.email,
            role: user.role,
        });
        const refreshToken = (0, jwt_util_1.generateRefreshToken)(user._id.toString());
        user.refreshToken = refreshToken;
        yield user.save();
        // Set secure HttpOnly cookies
        (0, jwt_util_1.setAuthCookies)(res, accessToken, refreshToken);
        return res.status(200).json({
            message: 'Email verified successfully! You are now logged in.',
            user: user.toSafeUser(),
        });
    }
    catch (error) {
        console.error('Email verification error:', error);
        return res.status(500).json({ error: 'Server error during email verification.' });
    }
});
exports.verifyEmail = verifyEmail;
/**
 * Resend Verification Email
 */
const resendVerificationEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: 'Email is required.' });
        }
        const user = yield user_model_1.default.findOne({ email: email.toLowerCase().trim() }).select('+verificationToken +verificationTokenExpires');
        if (user && !user.isEmailVerified) {
            const verificationToken = (0, email_util_1.generateSecureToken)();
            user.verificationToken = verificationToken;
            user.verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
            yield user.save();
            yield (0, email_util_1.sendVerificationEmail)(user.email, verificationToken);
        }
        // Generic response to avoid email enumeration
        return res.status(200).json({
            message: 'If an unverified account exists with that email address, a new verification link has been sent.',
        });
    }
    catch (error) {
        console.error('Resend verification error:', error);
        return res.status(500).json({ error: 'Server error processing request.' });
    }
});
exports.resendVerificationEmail = resendVerificationEmail;
/**
 * Login Controller
 * Authenticates credentials and issues HttpOnly JWT cookies.
 */
const login = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            yield logAuthEvent(req, {
                action: 'login_attempt_rejected',
                status: 'denied',
                severity: 'low',
                metadata: { reason: 'missing_email_or_password' },
                errorCode: 'MISSING_CREDENTIALS',
            });
            return res.status(400).json({ error: 'Email and password are required.' });
        }
        const user = yield user_model_1.default.findOne({ email: email.toLowerCase().trim() }).select('+password +refreshToken');
        // Timing-attack safe generic rejection
        if (!user) {
            yield logAuthEvent(req, {
                action: 'login_failed',
                status: 'failure',
                severity: 'medium',
                metadata: { email: email.toLowerCase().trim().slice(0, 64) },
                errorCode: 'INVALID_EMAIL_OR_PASSWORD',
            });
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        const isMatch = yield user.comparePassword(password);
        if (!isMatch) {
            yield logAuthEvent(req, {
                action: 'login_failed',
                status: 'failure',
                severity: 'medium',
                actorId: user._id.toString(),
                actorType: 'user',
                metadata: { email: user.email },
                errorCode: 'INVALID_PASSWORD',
            });
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        // Dual-token issuance
        const accessToken = (0, jwt_util_1.generateAccessToken)({
            userId: user._id.toString(),
            email: user.email,
            role: user.role,
        });
        const refreshToken = (0, jwt_util_1.generateRefreshToken)(user._id.toString());
        user.refreshToken = refreshToken;
        yield user.save();
        yield logAuthEvent(req, {
            action: 'login_successful',
            status: 'success',
            severity: 'low',
            actorId: user._id.toString(),
            actorType: user.role === 'admin' ? 'admin' : 'user',
            resourceType: 'session',
            resourceId: user._id.toString(),
            metadata: { email: user.email, role: user.role },
        });
        // Send tokens via HttpOnly, Secure, SameSite=Strict cookies
        (0, jwt_util_1.setAuthCookies)(res, accessToken, refreshToken);
        return res.status(200).json({
            message: 'Login successful.',
            user: user.toSafeUser(),
        });
    }
    catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Server error during login.' });
    }
});
exports.login = login;
/**
 * Refresh Token Controller
 * Rotates Access & Refresh tokens using the HttpOnly refresh token cookie.
 */
const refreshTokenController = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const refreshToken = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({
                error: 'No refresh token provided in session.',
                code: 'NO_REFRESH_TOKEN',
            });
        }
        let decoded;
        try {
            decoded = (0, jwt_util_1.verifyRefreshToken)(refreshToken);
        }
        catch (err) {
            (0, jwt_util_1.clearAuthCookies)(res);
            return res.status(401).json({
                error: 'Refresh token is expired or invalid.',
                code: 'INVALID_REFRESH_TOKEN',
            });
        }
        const user = yield user_model_1.default.findById(decoded.userId).select('+refreshToken');
        // Token reuse detection or revoked session
        if (!user || user.refreshToken !== refreshToken) {
            if (user) {
                // Invalidate compromised token
                user.refreshToken = null;
                yield user.save();
            }
            (0, jwt_util_1.clearAuthCookies)(res);
            return res.status(403).json({
                error: 'Invalid session or refresh token reuse detected.',
                code: 'SESSION_REVOKED',
            });
        }
        // Token rotation: Issue fresh access token and fresh refresh token
        const newAccessToken = (0, jwt_util_1.generateAccessToken)({
            userId: user._id.toString(),
            email: user.email,
            role: user.role,
        });
        const newRefreshToken = (0, jwt_util_1.generateRefreshToken)(user._id.toString());
        user.refreshToken = newRefreshToken;
        yield user.save();
        (0, jwt_util_1.setAuthCookies)(res, newAccessToken, newRefreshToken);
        return res.status(200).json({
            message: 'Session refreshed successfully.',
            user: user.toSafeUser(),
        });
    }
    catch (error) {
        console.error('Refresh token error:', error);
        (0, jwt_util_1.clearAuthCookies)(res);
        return res.status(500).json({ error: 'Server error refreshing session.' });
    }
});
exports.refreshTokenController = refreshTokenController;
/**
 * Logout Controller
 * Revokes refresh token in database and purges HttpOnly auth cookies.
 */
const logout = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        const refreshToken = (_b = req.cookies) === null || _b === void 0 ? void 0 : _b.refreshToken;
        let actorId;
        if (refreshToken) {
            try {
                const decoded = (0, jwt_util_1.verifyRefreshToken)(refreshToken);
                actorId = decoded.userId;
                yield user_model_1.default.findByIdAndUpdate(decoded.userId, { refreshToken: null });
            }
            catch (err) {
                // Token could already be expired; proceed to purge cookies
            }
        }
        yield logAuthEvent(req, {
            action: 'logout_successful',
            status: 'success',
            severity: 'informational',
            actorId,
            actorType: actorId ? 'user' : 'anonymous',
            resourceType: 'session',
            resourceId: actorId,
            metadata: { sessionRevoked: Boolean(actorId) },
        });
        (0, jwt_util_1.clearAuthCookies)(res);
        return res.status(200).json({ message: 'Logged out successfully.' });
    }
    catch (error) {
        console.error('Logout error:', error);
        (0, jwt_util_1.clearAuthCookies)(res);
        return res.status(500).json({ error: 'Server error during logout.' });
    }
});
exports.logout = logout;
/**
 * Get Current User Controller (Protected)
 */
const getCurrentUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        if (!req.user || !req.user.userId) {
            return res.status(401).json({ error: 'Unauthorized.' });
        }
        const user = yield user_model_1.default.findById(req.user.userId);
        if (!user) {
            (0, jwt_util_1.clearAuthCookies)(res);
            return res.status(404).json({ error: 'User not found.' });
        }
        return res.status(200).json({
            user: user.toSafeUser(),
        });
    }
    catch (error) {
        console.error('getCurrentUser error:', error);
        return res.status(500).json({ error: 'Server error retrieving user.' });
    }
});
exports.getCurrentUser = getCurrentUser;
const updateProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _c;
    try {
        if (!((_c = req.user) === null || _c === void 0 ? void 0 : _c.userId)) {
            res.status(401).json({ error: 'Unauthorized.' });
            return;
        }
        const displayName = typeof req.body.displayName === 'string' ? req.body.displayName.trim() : '';
        const avatarUrl = typeof req.body.avatarUrl === 'string' ? req.body.avatarUrl.trim() : '';
        if (displayName.length > 80 || avatarUrl.length > 500) {
            res.status(400).json({ error: 'Profile details exceed the allowed length.' });
            return;
        }
        const user = yield user_model_1.default.findByIdAndUpdate(req.user.userId, { displayName, avatarUrl }, { new: true, runValidators: true });
        if (!user) {
            res.status(404).json({ error: 'User not found.' });
            return;
        }
        yield logAuthEvent(req, {
            action: 'profile_updated',
            status: 'success',
            severity: 'low',
            actorId: user._id.toString(),
            actorType: user.role === 'admin' ? 'admin' : 'user',
            resourceType: 'profile',
            resourceId: user._id.toString(),
        });
        res.status(200).json({ user: user.toSafeUser() });
    }
    catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Unable to update profile.' });
    }
});
exports.updateProfile = updateProfile;
/**
 * OTP Verification Controller (Legacy flow)
 */
const verifyOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { otp, email } = req.body;
        const resetToken = yield resetToken_model_1.default.findOne({ otp, email });
        if (resetToken !== null) {
            return res.status(200).json({ token: resetToken.token });
        }
        return res.status(404).json({ error: 'Invalid token' });
    }
    catch (error) {
        return res.status(500).json({ error });
    }
});
exports.verifyOtp = verifyOtp;
/**
 * Reset Password Controller (Legacy flow)
 */
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { password } = req.body;
        const resetToken = yield resetToken_model_1.default.find({ password });
        if (resetToken.length > 0) {
            return res.status(200).json({ resetToken });
        }
        return res.status(404).json({ error: 'User not found' });
    }
    catch (error) {
        return res.status(500).json({ error });
    }
});
exports.resetPassword = resetPassword;
