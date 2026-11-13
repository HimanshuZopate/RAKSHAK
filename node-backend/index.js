"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const http_1 = __importDefault(require("http"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const mogoClient_1 = require("./conn/mogoClient");
const index_1 = __importDefault(require("./routes/index"));
const rateLimiter_1 = require("./middleware/rateLimiter");
const wafMiddleware_1 = require("./middleware/wafMiddleware");
const serviceSocket_1 = require("./socket/serviceSocket");
const service_model_1 = require("./model/service.model");
const aiProviderService_1 = require("./services/aiProviderService");
const orchestrator_1 = require("./services/vulnScanner/orchestrator");
const app = (0, express_1.default)();
const port = process.env.PORT || 3001;
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
// 1. HTTP Security Headers with Helmet
app.use((0, helmet_1.default)({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", clientUrl, 'ws:', 'wss:'],
        },
    },
    crossOriginEmbedderPolicy: false,
}));
// 2. Strict CORS Policy
app.use((0, cors_1.default)({
    origin: (origin, callback) => {
        const allowedOrigins = [clientUrl, 'http://localhost:3000', 'http://192.168.56.1:3000'];
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            callback(new Error(`Origin ${origin} not allowed by strict CORS policy.`));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie'],
}));
// 3. Body parsers and Cookie parser
app.use((0, cookie_parser_1.default)());
// AI chat requests carry recent conversation history (several assistant replies),
// which does not fit the strict 10kb default. Only /api/ai gets the larger limit;
// the controller still enforces per-field limits (question, context, history).
const defaultJsonParser = express_1.default.json({ limit: '10kb' });
const aiJsonParser = express_1.default.json({ limit: '64kb' });
app.use((req, res, next) => (req.path.startsWith('/api/ai/') ? aiJsonParser : defaultJsonParser)(req, res, next));
app.use(express_1.default.urlencoded({ extended: true, limit: '10kb' }));
// 4. Connect to MongoDB and seed default services
(0, mogoClient_1.connectDB)().then(() => {
    (0, service_model_1.seedServices)();
    (0, orchestrator_1.recoverInterruptedScans)(); // web scans left "running" by a previous process
});
// 6. Base Health Check
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        system: 'Rakshak Security Operations API',
        version: '2.1.0-socket-ready',
    });
});
// 7. Mount Web Application Firewall (WAF) & API routes with general rate limiter
app.use('/api', wafMiddleware_1.wafMiddleware, rateLimiter_1.apiLimiter, index_1.default);
// 8. Global Error Handler
// Stack traces and internal paths are logged server-side only — never sent to clients.
app.use((err, req, res, next) => {
    const status = Number((err === null || err === void 0 ? void 0 : err.status) || (err === null || err === void 0 ? void 0 : err.statusCode)) || 500;
    if (status >= 500)
        console.error('Unhandled Server Error:', err);
    else
        console.warn(`Request rejected (${status} ${(err === null || err === void 0 ? void 0 : err.type) || (err === null || err === void 0 ? void 0 : err.name) || 'error'}) on ${req.method} ${req.path}`);
    const known = {
        'entity.too.large': { code: 'PAYLOAD_TOO_LARGE', error: 'The request is too large.' },
        'entity.parse.failed': { code: 'INVALID_JSON', error: 'The request body is not valid JSON.' },
    };
    const mapped = known[err === null || err === void 0 ? void 0 : err.type];
    const isProduction = process.env.NODE_ENV === 'production';
    res.status(status).json({
        success: false,
        code: (mapped === null || mapped === void 0 ? void 0 : mapped.code) || (status >= 500 ? 'INTERNAL_ERROR' : 'REQUEST_ERROR'),
        error: (mapped === null || mapped === void 0 ? void 0 : mapped.error) || (status >= 500 || isProduction ? 'Internal Server Error' : (err === null || err === void 0 ? void 0 : err.message) || 'Request error'),
    });
});
// 9. Create HTTP Server and bind Socket.io
const httpServer = http_1.default.createServer(app);
(0, serviceSocket_1.setupSocketIO)(httpServer);
httpServer.listen(port, () => {
    console.log(`🔒 Security Dashboard Server & Socket.io running on port ${port}`);
    console.log(`🌐 Strict CORS allowed origin: ${clientUrl}`);
    // Load AI provider keys from the environment and verify them (no secrets are logged).
    (0, aiProviderService_1.initializeAIProviders)().catch(() => undefined);
});
exports.default = app;
