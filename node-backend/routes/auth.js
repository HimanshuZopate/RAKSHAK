"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const auth_controller_1 = require("../controller/auth.controller");
const user_controller_1 = require("../controller/user.controller");
const auth_controller_2 = require("../controller/auth.controller");
const rateLimiter_1 = require("../middleware/rateLimiter");
const verifyToken_1 = require("../middleware/verifyToken");
const authRouter = express_1.default.Router();
// Status check
authRouter.get('/', (req, res) => {
    res.json({ status: 'Authentication service active', secure: true });
});
// 1. Local Authentication (Rate-limited to prevent brute forcing)
authRouter.post('/register', rateLimiter_1.authLimiter, auth_controller_1.register);
authRouter.post('/login', rateLimiter_1.authLimiter, auth_controller_1.login);
authRouter.post('/refresh', auth_controller_1.refreshTokenController);
authRouter.post('/logout', auth_controller_1.logout);
// 2. Email Verification Endpoints
authRouter.get('/verify-email', auth_controller_1.verifyEmail);
authRouter.post('/verify-email', auth_controller_1.verifyEmail);
authRouter.post('/resend-verification', rateLimiter_1.emailLimiter, auth_controller_1.resendVerificationEmail);
// 3. User Identity Endpoint (Protected via verifyToken HttpOnly cookie)
authRouter.get('/me', verifyToken_1.verifyToken, auth_controller_1.getCurrentUser);
authRouter.patch('/profile', verifyToken_1.verifyToken, auth_controller_1.updateProfile);
// 4. Password Reset (Protected by rate limiter)
authRouter.post('/forgot', rateLimiter_1.authLimiter, user_controller_1.forgotPassword);
authRouter.post('/verify', rateLimiter_1.authLimiter, auth_controller_2.verifyOtp);
authRouter.post('/newpassword', rateLimiter_1.authLimiter, user_controller_1.setNewPassword);
authRouter.post('/reset', rateLimiter_1.authLimiter, user_controller_1.forgotPassword);
exports.default = authRouter;
