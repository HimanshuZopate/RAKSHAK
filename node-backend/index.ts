import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { connectDB } from './conn/mogoClient';
import router from './routes/index';
import { apiLimiter } from './middleware/rateLimiter';
import { wafMiddleware } from './middleware/wafMiddleware';
import { setupSocketIO } from './socket/serviceSocket';
import { seedServices } from './model/service.model';
import { initializeAIProviders } from './services/aiProviderService';

const app = express();
const port = process.env.PORT || 3001;
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';

// 1. HTTP Security Headers with Helmet
app.use(
  helmet({
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
  })
);

// 2. Strict CORS Policy
app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [clientUrl, 'http://localhost:3000', 'http://192.168.56.1:3000'];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Origin ${origin} not allowed by strict CORS policy.`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie'],
  })
);

// 3. Body parsers and Cookie parser
app.use(cookieParser());
// AI chat requests carry recent conversation history (several assistant replies),
// which does not fit the strict 10kb default. Only /api/ai gets the larger limit;
// the controller still enforces per-field limits (question, context, history).
const defaultJsonParser = express.json({ limit: '10kb' });
const aiJsonParser = express.json({ limit: '64kb' });
app.use((req, res, next) =>
  (req.path.startsWith('/api/ai/') ? aiJsonParser : defaultJsonParser)(req, res, next)
);
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 4. Connect to MongoDB and seed default services
connectDB().then(() => {
  seedServices();
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
app.use('/api', wafMiddleware, apiLimiter, router);

// 8. Global Error Handler
// Stack traces and internal paths are logged server-side only — never sent to clients.
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  const status = Number(err?.status || err?.statusCode) || 500;
  if (status >= 500) console.error('Unhandled Server Error:', err);
  else console.warn(`Request rejected (${status} ${err?.type || err?.name || 'error'}) on ${req.method} ${req.path}`);

  const known: Record<string, { code: string; error: string }> = {
    'entity.too.large': { code: 'PAYLOAD_TOO_LARGE', error: 'The request is too large.' },
    'entity.parse.failed': { code: 'INVALID_JSON', error: 'The request body is not valid JSON.' },
  };
  const mapped = known[err?.type];
  const isProduction = process.env.NODE_ENV === 'production';
  res.status(status).json({
    success: false,
    code: mapped?.code || (status >= 500 ? 'INTERNAL_ERROR' : 'REQUEST_ERROR'),
    error: mapped?.error || (status >= 500 || isProduction ? 'Internal Server Error' : err?.message || 'Request error'),
  });
});

// 9. Create HTTP Server and bind Socket.io
const httpServer = http.createServer(app);
setupSocketIO(httpServer);

httpServer.listen(port, () => {
  console.log(`🔒 Security Dashboard Server & Socket.io running on port ${port}`);
  console.log(`🌐 Strict CORS allowed origin: ${clientUrl}`);
  // Load AI provider keys from the environment and verify them (no secrets are logged).
  initializeAIProviders().catch(() => undefined);
});

export default app;
