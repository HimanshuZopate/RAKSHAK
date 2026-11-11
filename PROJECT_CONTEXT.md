# RAKSHAK — PROJECT CONTEXT (Knowledge Base)

> Source of truth: static analysis of the repository at `d:\MCA\Second Year\Major Project\RAKSHAK` (2026-11-11). The folder is **not a git repository**, so there is no commit history. "Development history" is inferred from code artifacts and labelled as inference.

## 1. Project Executive Summary
- **Name:** RAKSHAK ("protector"). The frontend package is named `vul-system` and the backend package `backend`. The page title is "Rakshak | Security Operations Platform". The API health check reports `system: 'Rakshak Security Operations API', version: '2.1.0-socket-ready'`.
- **Type:** MCA second-year major project. It is a MERN-stack (MongoDB, Express, React, Node) cybersecurity platform with a TypeScript backend.
- **Purpose:** a single dashboard of security tools: phishing and scam detection, a website security-header and TLS scanner, an uploaded-file malware and secret scanner, CVE lookup, a client and browser network audit, password strength analysis and generation, an interactive cybersecurity simulation lab, an AI security assistant ("AI RAKSHAK"), audit logs, and a built-in WAF with live traffic monitoring.
- **Lineage (inferred):** the project grew out of a deliberately vulnerable "MERN Stack Web Security Testing Ground". The README still describes that project. `otp_script.py` brute-forces the OTP endpoint, and the reset screens say "This page has a login vulnerability…". The legacy OTP/reset flow is still intentionally weak.
- **Target users:** general users and students who want security awareness tools. The content is India-focused: helpline 1930, cybercrime.gov.in, CERT-In.
- **Status:** most modules are working end to end. Several have serious bugs (§14), and there are major security gaps in auth, WAF and scanners. No automated tests exist.

## 2. Project Objectives and Requirements (from code)
- Authenticated users reach security tools from a dashboard of "services" stored in MongoDB.
- Each tool returns explainable results: risk score, warning signs, remediation steps, disclaimers and limitations.
- Defensive posture of the platform itself: Helmet CSP, strict CORS, rate limiting, a custom WAF, SSRF protection (website scanner only), audit logging, and HttpOnly-cookie JWT sessions with refresh rotation.
- Privacy: password analysis is 100% client-side, and AI prompts and audit metadata are scrubbed.
- An AI assistant with multiple LLM providers and an offline rule-based fallback.

## 3. Complete Technology Stack
**Implemented, frontend** (root `package.json`)
- React 18.2 on Create React App (`react-scripts` 5.0.1), react-router-dom 6.14.
- axios 1.4 and socket.io-client 4.8.
- Tailwind CSS 3.3 with daisyUI 3.2. daisyUI sits in devDependencies even though it is used at runtime.
- framer-motion 10 for animation and recharts 3 for charts.
- lucide-react (primary icons) and @iconify/react (Fluent and Noto icons).
- jspdf 4.2.1 with jspdf-autotable 5.0.8 for PDF export.
- No TypeScript on the frontend; files are plain JS/JSX.

**Implemented, backend** (`node-backend/package.json`)
- Node.js with TypeScript 5.1, run through **ts-node** in both `dev` and `start`. The compiled `.js` files sit next to the `.ts` files because there is no `outDir`. Until 2026-11-11 Node resolved those stale `.js` siblings *before* the `.ts` sources for every imported module; `tsconfig.json` now sets `"ts-node": { "preferTsExts": true }` so the `.ts` sources are loaded. Keep the `.js` in sync with `npm run build`.
- Locally installed Node version observed: v24.13.1.
- Express 4.18.2, Mongoose 7.3.4 (MongoDB), socket.io 4.8.
- helmet 8, cors, cookie-parser, express-rate-limit 8.
- jsonwebtoken 9, bcryptjs 3 (12 salt rounds), multer 2 (uploads), nodemailer 10 (SMTP, or an Ethereal fallback).
- clamscan 2.4 (ClamAV wrapper), officeparser 8.1.1, systeminformation 5, geoip-lite 2, uuid 14, axios, dotenv.

**Third-party APIs (implemented)**
- Groq (`https://api.groq.com/openai/v1/chat/completions`, default `llama-3.1-8b-instant`).
- Google Gemini (`generativelanguage.googleapis.com/v1beta`, default `gemini-1.5-flash`; the key is sent as a URL query string).
- OpenAI (`gpt-4o-mini`).
- NVD CVE API 2.0 (no API key).
- ipify (public IP lookup in the client audit).
- Google STUN (browser WebRTC leak test).
- DiceBear avatars.
- All LLM calls use raw axios; there are no vendor SDKs.

**Declared but unused, or planned:** `node-cron`, backend `socket.io-client`, `cookie`. The `GOOGLE_CLIENT_ID/SECRET/CALLBACK_URL` entries in `.env.example` and the passport packages present in `node_modules` (not in package.json) suggest Google OAuth was **planned or removed and is not implemented**. The `node-backend/config/` folder is empty.

**Env var names** (`.env.example`): PORT, NODE_ENV, CLIENT_URL, MONGO_URI, ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET, ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY, GOOGLE_* (unused), SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM, AI_ENABLED, AI_PROVIDER, GROQ_API_KEY, GROQ_MODEL, GEMINI_API_KEY, GEMINI_MODEL, OPENAI_API_KEY, OPENAI_MODEL, AI_REQUEST_TIMEOUT_MS.
- The code also reads `TEMP_UPLOAD_DIR`, which is undocumented.
- The frontend reads `REACT_APP_API_URL` (default `http://localhost:3001/api`) and `REACT_APP_SOCKET_URL` (default `http://localhost:3001`).

## 4. Application Architecture
- **Two separate apps:**
  - CRA SPA at the repo root, port 3000.
  - Express API with Socket.io in `node-backend/`, port 3001.
  - They run on different origins. Credentialed CORS is used, and there is no CRA proxy.
- **Backend layering:** `routes/` → `middleware/` → `controller/` → `services/` and `scanners/` → `model/` (Mongoose). Some routes keep their logic inline (`routes/services.ts`, `routes/waf.ts`). There is no DI container: modules import each other directly, and state is held in module scope (WAF config, AI runtime keys).
- **Request pipeline** (`node-backend/index.ts`):
  1. dotenv
  2. helmet (custom CSP)
  3. CORS. Allow-list: CLIENT_URL, localhost:3000, 192.168.56.1:3000. Methods GET/POST/PUT/DELETE/OPTIONS; **PATCH is missing**.
  4. cookieParser
  5. JSON and urlencoded parsers, each limited to 10kb
  6. `connectDB().then(seedServices)`, not awaited
  7. `GET /` health check
  8. `app.use('/api', wafMiddleware, apiLimiter, router)`
  9. Global error handler (shows the stack outside production)
  10. http server with `setupSocketIO`
- **Auth model:** JWT access token (15m) and refresh token (7d) in HttpOnly cookies named `accessToken` and `refreshToken`, set with sameSite strict and secure only in production. `verifyToken` reads the cookie first, then `Authorization: Bearer`. Refresh rotation includes reuse detection. The frontend axios interceptor silently refreshes on 401.
- **Real-time:** Socket.io authenticates at the handshake from the cookie or `handshake.auth.token`. Events:
  - Client → server: `start-service-execution {serviceId, targetId}`.
  - Server → client: `log-update`, `scan-complete`, `execution-error`, and `live-traffic-update` (WAF traffic broadcast to all sockets).
- **Frontend:** `index.js` sets up BrowserRouter. `App.js` wraps everything in AuthProvider and declares Routes. `ProtectedRoute` shows an inline sign-in card rather than redirecting. API calls go through `src/utils/api.js`.
- **Service dispatch:** `/service/:id` (ServiceDetailScreen) renders a dedicated screen based on the serviceId:

  | serviceId | Screen rendered |
  |---|---|
  | 1 | FileScannerScreen |
  | 2 | PhishingDetectorScreen |
  | 3 | ClientAuditScreen |
  | 7 | PasswordSecurityScreen |
  | 8 | WebsiteSecurityScreen |
  | any other | Generic socket-driven execution UI with targets |

## 5. Folder Structure
```
RAKSHAK/
├─ package.json, tailwind.config.js, README.md (stale), .gitignore, otp_script.py
├─ public/ (index.html, manifest.json, icons)      ├─ build/ (CRA production build, 2026-10-15)
├─ src/
│  ├─ index.js, App.js, App.css (landing/auth/profile/notification/ai-* custom CSS), index.css
│  ├─ context/AuthContext.jsx
│  ├─ components/ ProtectedRoute.jsx, CreateTargetModal.jsx, VulnerabilityScanner.jsx
│  ├─ screens/ LandingPage, LoginScreen, SignupScreen, VerifyEmailScreen, ResetPasword, NewPasword,
│  │          DashboardScreen, ServiceDetailScreen, VulnerabilitiesScreen, PhishingDetectorScreen,
│  │          ClientAuditScreen, SecurityAuditsScreen, FileScannerScreen, PasswordSecurityScreen,
│  │          WebsiteSecurityScreen, SimulationLabPage, AIRakshakScreen, ProfileScreen, NotificationsScreen
│  │  └─ components/ OtpModal, LoadingScreen, SuccessModal (unused), FailureModal
│  ├─ utils/ api.js, axios.js (shim), browserAudit.js, passwordAnalyzer.js, passwordGenerator.js,
│  │         pdfGenerator.js, simProgress.js, simulationScenarios.js, icons.js
│  └─ assets/ (png images)
└─ node-backend/
   ├─ index.ts, tsconfig.json, package.json, .env(.example), types/clamscan.d.ts
   ├─ conn/mogoClient.ts (sic)      ├─ config/ (empty)
   ├─ routes/ index, auth, services, target, scanners, audits, waf, phishing, websiteSecurity, ai
   ├─ controller/ auth.controller, user.controller, target.controller, scanners, auditController,
   │              phishing.controller, websiteSecurity.controller, aiController
   ├─ middleware/ verifyToken, rateLimiter, fileUpload, wafMiddleware
   ├─ model/ user, resetToken, target, scanReport, service, wafConfig, trafficLog, auditLog
   ├─ services/ aiOrchestrator, aiProviderService, groqService (dead), cyberIntelligenceEngine,
   │            knowledgeBase, auditService, fileScanner, nvdScanner,
   │            websiteScanner/{ssrfProtection, tlsScanner, headerScanner, scoreCalculator}
   ├─ scanners/ portScanner, headerScanner, systemAuditor, fileMonitor, malwareScanner (socket-driven)
   ├─ socket/serviceSocket.ts       └─ util/ jwt.util, email.util, generateOtp, generateResetToken
```
Every backend `.ts` file has a compiled `.js` file beside it. **Always edit the `.ts` file**, then run `npm run build` so the `.js` siblings don't go stale (ts-node prefers `.ts` via `preferTsExts`). `tests/` (node:test, `npm run test:ai`) is excluded from the build.

## 6. Module-Wise Implementation Details

### 6.1 Authentication and Accounts
- **Files:**
  - Backend: `routes/auth.ts`, `controller/auth.controller.ts`, `controller/user.controller.ts`, `middleware/verifyToken.ts`, `middleware/rateLimiter.ts`, `util/jwt.util.ts`, `util/email.util.ts`, `util/generateOtp.ts`, `util/generateResetToken.ts`, `model/user.model.ts`, `model/resetToken.model.ts`.
  - Frontend: `context/AuthContext.jsx`, `utils/api.js`, `components/ProtectedRoute.jsx`, `LoginScreen`, `SignupScreen`, `VerifyEmailScreen`, `ProfileScreen`, and the legacy `ResetPasword`, `OtpModal` and `NewPasword`.
- **Register:** validates email and password strength (≥8 characters with upper, lower, digit and special). **It sets `isEmailVerified: true` right away**, which bypasses verification. It then sets cookies.
- **Login:** bcrypt compare and refresh-token rotation; the token is stored in **plain text** in `user.refreshToken`. Login does **not** check `isEmailVerified`.
- **Refresh:** reads the refresh cookie. A mismatch triggers revocation and returns 403 `SESSION_REVOKED`.
- **Logout:** clears the stored token and the cookies.
- **Other endpoints:** `/me` returns the current user. `PATCH /profile` updates `displayName` and `avatarUrl`. Any field left out of the request is wiped, and `avatarUrl` is not validated as a URL.
- **Email verification:** a 32-byte token valid for 24h, sent with nodemailer. The link format is `${CLIENT_URL}/verify-email?token=`. GET and POST are both accepted.
- **Legacy reset flow** (insecure, possibly a deliberate training target):
  - `POST /auth/forgot` (or `/reset`) creates a ResetToken with a 4-digit OTP from `Math.random` and **returns the reset token in the response**. The OTP is never emailed; it is only written to the console.
  - `POST /auth/verify {otp,email}` returns the token.
  - `POST /auth/newpassword {password,token}` sets the password with **no strength check and no expiry**. It returns the full user document **including the password hash**, and it **hangs** if the token isn't found.
  - The queries are open to NoSQL operator injection.
- **Rate limits:**
  - `authLimiter`: 5 requests per 15 minutes, with one instance **shared by all auth routes**.
  - `emailLimiter`: 3 per hour.
  - `apiLimiter`: 200 per 15 minutes.
- **Dead code:** `auth.controller.resetPassword` and `user.controller.register`.

### 6.2 Dashboard and Services Catalog
- **Files:** `routes/services.ts` (inline handlers, verifyToken), `model/service.model.ts` (`seedServices`, `defaultServices`), `DashboardScreen.jsx`, `ServiceDetailScreen.jsx`.
- **Seeded services (5):**

  | serviceId | Name |
  |---|---|
  | 1 | Vulnerability Scanner |
  | 2 | Phishing & Scam Detector |
  | 3 | Security Audits |
  | 7 | Password Security Lab |
  | 8 | Website Security Scanner |

  IDs 4, 5 and 6 (intrusion detection, API monitoring, encryption) were **retired** and are deleted during seeding. Comments still say "6 services".
- **Seeding behaviour:** `GET /services` re-seeds if the collection is empty or if service 2's name has drifted.
- **Dashboard (frontend):** also filters out retired services, rewrites service 2, and **synthesizes cards for 7 and 8** if they are missing. The dashboard has a collapsible sidebar, a mobile drawer, search, and an "Ask AI RAKSHAK" button.
- `service.lastRun` and `service.status` are **global** and shared across all users.

### 6.3 Targets and Socket Service Execution (generic scanner UI)
- **Files:** `routes/target.ts`, `controller/target.controller.ts`, `model/target.model.ts`, `model/scanReport.model.ts`, `socket/serviceSocket.ts`, `scanners/*`, `components/CreateTargetModal.jsx`, `ServiceDetailScreen.jsx`, `utils/pdfGenerator.js`.
- **Targets** have the fields `{name, host, environment: Production|Staging|Dev, techStack[{name,version}]}` and are scoped to the owning user for HTTP access.
- **Socket dispatch:** the `start-service-execution` handler loads the target with `TargetModel.findById` and **does not check ownership**. It then chooses scanners from the service name:
  - "vulnerability" or "host": `auditSystem` (the **RAKSHAK server's own** CPU, memory and connections), `checkFileIntegrity` (hashes `node-backend/model`, always returns `[]`) and `scanForMalware` (ClamAV on `model/`).
  - "port": `scanPorts(target.host, [21,22,80,443,3306,27017])`.
  - anything else: `scanHeaders(target.host)` with axios.
- **No SSRF protection on `target.host`.**
- Each run saves a `ScanReport` and emits `scan-complete`. The frontend shows a live terminal and exports the report to PDF.
- Note: services 1, 2, 3, 7 and 8 are all short-circuited to dedicated screens, so in practice this generic path is reached only for non-seeded IDs.
- **Dead code:** `generateLogsForService` and `activeIntervals`.

### 6.4 Vulnerability (CVE) Scanner
- **Files:** `routes/scanners.ts` (`POST /scanners/vulnerability`, **no auth**), `controller/scanners.ts`, `services/nvdScanner.ts`, `components/VulnerabilityScanner.jsx`, `VulnerabilitiesScreen.jsx`.
- **The target is never contacted.** `mockServiceDetection` returns `apache 2.4.49` if the target string contains "apache", otherwise `nginx 1.21` and `openssh 8.2`. It then runs an NVD keyword search (5 results, 1s delay between calls, no timeout).
- On HTTP 403 or 429 the backend **invents `CVE-MOCK-xxx` HIGH entries**.
- On any error the frontend **falls back to hardcoded mock CVEs**.
- The UI shows a recharts bar chart, a daisyUI table, a remediation modal (generic text) and a jsPDF report.
- Results are not persisted; only audit events are written.

### 6.5 File Scanner
- **Files:** `POST /scanners/analyze-file` (**no auth**), `middleware/fileUpload.ts`, `services/fileScanner.ts`, `FileScannerScreen.jsx`.
- **Upload rules:** multer disk storage at `TEMP_UPLOAD_DIR or os.tmpdir()/security-scans`, 15MB limit, MIME and extension must both be on the allow-list. The file is deleted in a `finally` block.
- **Engines:** ClamAV (clamscan) and 17 static regex rules run in parallel. The rules cover eval/exec, PowerShell -enc, WScript, VBA auto-run, AWS keys, PEM keys, GitHub tokens, generic secrets, IPs and URLs.
- **Verdicts:** Malicious if ClamAV hits or any finding is CRITICAL. Suspicious if any finding is HIGH, MEDIUM or **LOW** (a single URL is enough). Clean otherwise.
- **Bugs:**
  - officeparser v8 returns an AST object, so `.docx/.pptx/.xlsx/.pdf` text is scanned as `"[object Object]"` (`fileScanner.ts:226`).
  - The ClamAV options use snake_case names, which clamscan v2 ignores.
  - When ClamAV is missing the file can still be reported Clean.
  - Detected secrets are echoed back in full.
- **Frontend:** drag-and-drop, a simulated progress bar, a findings table and remediation tips. The request is a raw axios multipart call with a 90s timeout.

### 6.6 Phishing & Scam Detector
- **Files:** `routes/phishing.ts` (verifyToken, 60 requests per 15 min), `controller/phishing.controller.ts`, `PhishingDetectorScreen.jsx`.
- Heuristic only, with no external APIs.
- **`analyzeUrl`** runs 11 checks: IP host, suspicious TLD, shortener, brand impersonation, more than 4 subdomains, `@`, percent-encoding, length over 200, plain http, sensitive path keywords, punycode or Cyrillic.
- **`analyzeMessage`** looks at embedded URLs, 15 keyword patterns, urgency wording, requests for personal information, sender domain and grammar signals.
- **Risk score:** 0–100. Low is under 30, Medium is under 60, High is 60 or more.
- The UI has three modes: url, message and email_sms. It shows an SVG gauge, warning signs and recommended actions.
- **Issues:**
  - A non-string `senderInfo` causes a 500.
  - A 10000-character message can exceed the 10kb body limit.
  - The WAF blocks inputs that contain attack strings or `#` before they reach the detector.

### 6.7 Website Security Scanner
- **Files:**
  - Backend: `routes/websiteSecurity.ts`, mounted at both `/api/security` and `/api/website-security`, with paths `/website-scan` and `/scan`. It uses verifyToken and allows 30 requests per 15 min.
  - Also `controller/websiteSecurity.controller.ts` and `services/websiteScanner/{ssrfProtection,tlsScanner,headerScanner,scoreCalculator}.ts`.
  - Frontend: `WebsiteSecurityScreen.jsx`.
- **Flow:**
  1. `validateTargetUrl` (SSRF protection): http and https only; no credentials in the URL; localhost, `.local` and `.internal` blocked; DNS resolution with all private and reserved addresses blocked; ports limited to 80, 443, 8080 and 8443.
  2. TLS and header checks run in parallel:
     - `inspectTlsCertificate` uses `tls.connect` to the pinned IP with SNI and checks expiry (expiring within 30 days), hostname match and trust.
     - `inspectSecurityHeaders` sends a GET pinned to the IP, follows up to 3 redirects, checks HSTS, CSP, XCTO, XFO, Referrer-Policy and Permissions-Policy, and checks the HTTP→HTTPS redirect.
  3. `aggregateScanResults` produces a 100-point score: HTTPS 25, TLS 25, redirect 10, HSTS 15, CSP 10, XCTO 5, XFO 5, Referrer-Policy 3, Permissions-Policy 2. Grades: A ≥85, B ≥70, C ≥55, D ≥40, otherwise F.
- **CRITICAL BUG:** the custom `lookup` in `headerScanner.ts:75-77,175-177` returns a single IP string. Node 24 calls lookup with `{all:true}` and expects an array, so the request fails with `ERR_INVALID_IP_ADDRESS`. As a result every site shows "HTTPS Unavailable" with all headers Missing, and the score is at most about 25 (F).
- **Other issues:**
  - The HTTPS probe uses port 80 for `http://` input.
  - Headers are shown as "Missing" when they should be "Unable to Verify".
  - The TLS wildcard match lacks a dot boundary.
  - An expiring-soon status hides a mismatch or untrusted chain.
- **Frontend:** client-side URL and SSRF pre-check, a score ring, 4 pillar cards, a findings accordion, and a TLS certificate modal.

### 6.8 Client / Network Security Audit (service 3, "Security Audits")
- **Files:** `POST /audits/client` (verifyToken), `controller/auditController.ts` (`runClientAudit`, `scanPort`, `resolvePublicIp`, `calculateSecurityScore`, `generateRecommendations`), `src/utils/browserAudit.js`, `ClientAuditScreen.jsx`.
- **Browser side:** collects telemetry for the UA and outdated-browser check, a WebRTC local-IP leak test, WebGL fingerprinting, a fingerprint score and HTTPS.
- **Server side:** resolves the client IP from **X-Forwarded-For (trusted blindly)**, then the socket address, then ipify. It TCP-scans 10 "dangerous" ports on that IP with a 2s timeout. Because XFF is trusted, the server can be made to port-scan any public IP.
- The result includes a score, recommendations and an overall risk.

### 6.9 Audit Logging and Notifications
- **Files:** `services/auditService.ts` (`recordAuditEvent`, `sanitizeMetadata`, `getActorContext`, `safeUrlPreview`, `getRequestId`), `model/auditLog.model.ts`, `routes/audits.ts`, `controller/auditController.ts` (`listAuditLogs`, `getAuditLogById`), `SecurityAuditsScreen.jsx`, `NotificationsScreen.jsx`.
- Every module records audit events.
- **Metadata sanitisation:** drops keys whose names look sensitive (key names only, not values), caps strings at 255 characters, arrays at 10 items, depth at 3 and objects at 12 keys. A failed write never throws; it returns false.
- **List endpoint:** paginated with a limit of 50. Non-admins are restricted to their own `actorId`. The `action` filter is an unescaped regex.
- **Detail endpoint:** admin only. Looking up by `eventId` causes a CastError and a 500.
- `SecurityAuditsScreen` (at `/security-audits`) is **not linked from any navigation**, and the file is **not valid UTF-8** (Windows-1252 bytes show up as `�`).
- `NotificationsScreen` combines `/audits?limit=50` with `/ai/recommendations`.

### 6.10 WAF and Live Traffic
- **Files:** `middleware/wafMiddleware.ts`, `model/wafConfig.model.ts`, `model/trafficLog.model.ts`, `routes/waf.ts`.
- **Rules:** 17 regex rules: 6 SQLi, 5 XSS, 4 path traversal and 2 command injection. They inspect the URL, query, body (including keys, up to depth 6), user-agent, referer and `x-payload-test`, in both raw and decoded form.
- **Modes:** `active` (blocks with 403) or `simulation`.
- Geolocation comes from geoip-lite. The IP is taken from XFF, then `x-real-ip`, then `x-simulated-ip`. The `x-mock-country` and `x-mock-city` headers can override the location.
- **Logging and broadcast:** a TrafficLog row is written for **every** `/api` request, with no retention policy. Each row is broadcast to all sockets.
- **Unauthenticated endpoints:** `/api/waf/logs` (GET and DELETE), `/stats`, `/config` (GET and POST, no validation) and `/simulate`.
- **Problems:**
  - The rule `/(?:--\s*|\/\*.*?\*\/|#\s*)/m` blocks any `#` or `--`, which includes valid passwords such as `Abc#1234`.
  - POST bodies, **including login passwords**, are stored in `payload` (first 150 characters), broadcast to all sockets and readable without auth.
  - The search filter is an unescaped `$regex`.
  - The stats timeline mixes UTC and local time.
- **No frontend screen was found** that consumes `/api/waf/*` or `live-traffic-update`. UNVERIFIED whether a UI was planned.

### 6.11 AI RAKSHAK Assistant (repaired 2026-11-11)
- **Files:** `routes/ai.ts`, `controller/aiController.ts`, `services/aiOrchestrator.ts`, `services/aiProviderService.ts`, `services/llmKeyPool.ts` (new), `services/cyberIntelligenceEngine.ts`, `services/knowledgeBase.ts`, `services/groqService.ts` (dead), `src/screens/AIRakshakScreen.jsx`, tests in `node-backend/tests/aiProvider.test.ts`.
- **Endpoints:**

  | Method | Path | Auth |
  |---|---|---|
  | GET | `/ai/status` → `{success, status}` (per-key detail for admins only) | optional |
  | POST | `/ai/chat {question ≤2000, context? ≤4000, history?[{role:user\|assistant, content}]}` | optional |
  | POST | `/ai/explain {finding}` | optional |
  | GET | `/ai/recommendations` | required |
  | POST | `/ai/configure {preferredProvider: auto\|gemini\|groq\|openai\|offline}` | **admin only**; API keys are rejected (env-only) |

- **Keys:** `GEMINI_API_KEY_1..3` (up to `_10`), plus the legacy `GEMINI_API_KEY` (merged and de-duplicated), `GROQ_API_KEY`, `OPENAI_API_KEY`. They are read from the environment only and never returned, logged or stored.
- **Models:** `GEMINI_MODEL=gemini-3.5-flash` with `GEMINI_THINKING_LEVEL=minimal`, and `GROQ_MODEL=openai/gpt-oss-20b`. Older Gemini models return 404 "no longer available to new users" on newer projects. `gemini-3.8-flash` and `gemini-flash-latest` hung for more than 30s on the free tier.
- **Failover chain per request:**
  - Order: preferred provider, then the Gemini pool (random key), then the other Gemini keys, then Groq, then OpenAI, then the offline engine.
  - Each key is tried at most once per request.
  - Each attempt has a 15s timeout (`AI_REQUEST_TIMEOUT_MS`); the whole request has a 30s budget (`AI_TOTAL_TIMEOUT_MS`).
  - The frontend chat timeout is 45s.
- **Errors and cooldowns** (`classifyLLMError` in `llmKeyPool.ts`):

  | Error | Effect on the key |
  |---|---|
  | Daily quota (429 with `QuotaFailure` `*PerDay*`, or `limit: 0`) | Cooldown until Pacific midnight |
  | Rate limit (429 RPM) | Cooldown from `RetryInfo` / `Retry-After`, default 60s, clamped 5s to 15min |
  | Server error or timeout | Exponential backoff 5s → 5min |
  | 401/403 or `API_KEY_INVALID` | Disabled until restart |
  | 404 (model unavailable for that key's project) | 1h cooldown |
  | Network or 400 | Not the key's fault; moves to the next provider |

- **Concurrency:** if another request has already recorded a failure for a key, the second failure is merged rather than counted twice.
- **Startup:** `initializeAIProviders()` in `index.ts` checks each key with Gemini `countTokens` (no generation quota used), or with the models endpoint for Groq and OpenAI.
- **Orchestrator:**
  - `sanitizeHistory` keeps only user/assistant turns, scrubs secrets, keeps the last 8 turns, drops leading assistant turns and drops a duplicated current question.
  - `fallbackUsed` and a user-facing `notice` are now set correctly.
  - `AI_ENABLED=false` and the `offline` preference now really skip external providers.
- **WAF:** for the exact routes `POST /api/ai/chat` and `/api/ai/explain`, body inspection is skipped. These bodies are free text sent only to the LLM, and Markdown `#` / `---` triggered the SQL-comment rule. URL, query and headers are still inspected, and the conversation body is not stored in `trafficlogs`.
- **Original root causes (fixed):**
  1. The WAF blocked every UI chat with 403, because the welcome message `### …` is part of the history.
  2. The Gemini model (1.5) and the Groq model (llama-3.1-8b-instant) were retired, and no Gemini key was set.
  3. The Gemini key was sent in the URL.
  4. The current question was duplicated in the history.
  5. The 10s frontend timeout was shorter than the backend's per-attempt timeout.
  6. Any user could overwrite the keys through `/ai/configure`.
- **UI/UX cleanup (2026-11-11, second pass):**
  - `AIRakshakScreen.jsx` shows no provider, mode, status, key or quota information. The settings modal, engine pill, category filters and provider tags were removed.
  - New layout: a minimal empty state with 4 suggestions, a typing indicator, and a "New chat" button.
  - Safe Markdown renderer (exported as `MarkdownMessage`): tables, rules, headings, nested and numbered lists that keep their numbering, fenced code, and only http(s)/mailto links.
  - Lifecycle fixes: a ref lock prevents double submits; the chat auto-scrolls only when you're near the bottom; an AbortController plus a conversation counter discard replies that arrive after "New chat".
  - Errors are friendly messages and never show internal codes.
  - CSS lives in the `ai-*` block of `App.css`. It sets `text-align: left` (to override the CRA `.App` centering) and an explicit `list-style` (to override the Tailwind preflight reset).
- **Backend (second pass):**
  - The system prompt was consolidated into `SYSTEM_PROMPT` in `aiOrchestrator.ts`: direct answers, cybersecurity scope, no claims of having scanned anything, defensive guidance only, and never revealing instructions, model or provider.
  - `/api/ai/*` has a 64kb JSON limit (10kb everywhere else). Long conversations had been failing with 413.
  - The global error handler never sends stack traces and returns `{success:false, code}`.
  - AI endpoints always include `success`.
  - The offline engine uses whole-word keyword matching, a greeting no longer overrides real topics, and the boilerplate and echoed context were removed.
- **Tests:** `node-backend` `npm run test:ai` (22 node:test cases); frontend `src/screens/AIRakshakScreen.test.js` (11 Jest/RTL cases, run with `npx react-scripts test --watchAll=false --testPathPattern=AIRakshakScreen`).

### 6.12 Password Security Lab (client-only)
- **Files:** `PasswordSecurityScreen.jsx` (routes `/password-security` and `/password-lab`), `utils/passwordAnalyzer.js`, `utils/passwordGenerator.js`.
- **Analyzer:** entropy, common-password list, keyboard and sequence patterns, leet-speak, years, repeats, crack-time estimates and indicators.
- **Generator:** CSPRNG with rejection sampling and a Fisher–Yates shuffle, plus a diceware passphrase mode. The word list contains duplicate words.
- Includes Myths vs Facts content. No backend calls.

### 6.13 Simulation Lab (client-only)
- **Files:** `SimulationLabPage.jsx`, `utils/simulationScenarios.js` (7 simulations: phishing, network, incident, malware, password, web, privacy), `utils/simProgress.js` (localStorage key `sim_lab_progress_v1`).
- Quizzes and scenarios. No backend calls.

### 6.14 Landing, Profile, Misc
- `LandingPage.jsx` is a public marketing page with hardcoded services and FAQs, styled with `landing-*` CSS.
- `ProfileScreen.jsx` edits the display name and avatar.

## 7. Complete Database Context
- **DB:** MongoDB through Mongoose 7. Connection string is `MONGO_URI`, with the fallback `mongodb://localhost:27017/mern_security?authMechanism=DEFAULT`.
- If the connection fails the error is only logged and seeding still runs.
- There are no migrations. Schema changes happen in code, with seeding in `seedServices()`.

**Collections (Mongoose default names):**
- **users** (`model/user.model.ts`):
  - `email` (required, unique, lowercase, regex)
  - `displayName` (≤80), `avatarUrl` (≤500)
  - `password` (required, min 8, bcrypt-hashed in a pre-save hook, **not `select:false`**)
  - `isEmailVerified` (default false)
  - `verificationToken`, `verificationTokenExpires`, `refreshToken` (all `select:false`)
  - `role` (enum user|admin)
  - timestamps
  - Methods: `comparePassword` and `toSafeUser`. The `toSafeUser` TypeScript type omits displayName and avatarUrl.
- **resettokens:**
  - `email` (required, unique), `token`, `otp`
  - The pre-save hook generates the OTP and token.
  - No expiry, no TTL, no attempt counter; values stored in plain text.
- **targets:**
  - `user` (ObjectId ref User, required), `name`, `host`, `environment` (enum Production|Staging|Dev), `techStack[{name, version}]`, `createdAt`
  - No index on `user`.
- **scanreports:**
  - `user` (ref User), `target` (ref Target), `service` (String), `status` (Success|Warning|Failed), `findings[{type, description, severity: LOW|MEDIUM|HIGH|CRITICAL}]`, `createdAt`
  - Written only by the socket. No HTTP endpoint reads it.
- **services:**
  - `serviceId` (Number, unique), `name` (unique), `description`
  - `status` (Active|Pending|Maintenance), `lastRun`
  - `iconKey`, `color`, `shadow`, `metrics` (UI styling)
  - `severity` (Critical|High|Medium|Low|None)
  - timestamps
- **wafconfigs:**
  - `mode` (active|simulation)
  - `sqlInjection`, `xss`, `pathTraversal`, `commandInjection`, `blockLocalTraffic` (unused), all Boolean
  - `updatedAt` (never refreshed)
- **trafficlogs:**
  - `ipAddress`, `method`, `endpoint`, `payload`
  - `threatType` (SQLi|XSS|Path Traversal|Command Injection|Suspicious|None)
  - `action` (Blocked|Allowed), `statusCode`
  - `country`, `countryCode`, `city`, `userAgent`, `ruleMatched`, `timestamp`
  - Several indexes. No TTL.
- **auditlogs:**
  - `eventId` (uuid, unique, plus a duplicate `index:true`), `timestamp`
  - `actorId`, `actorType` (system|anonymous|user|admin), `action`
  - `category` (authentication|security scan|phishing|simulation|administration|system)
  - `resourceType`, `resourceId`
  - `status` (success|failure|denied|partial)
  - `severity` (informational|low|medium|high|critical)
  - `source`, `requestId`, `metadata` (Mixed), `errorCode`
  - timestamps and compound indexes
- **Relationships:** Target.user → User, ScanReport.user → User, ScanReport.target → Target. AuditLog.actorId is a userId string, not a ref.

## 8. API Routes (all under `/api`; WAF and apiLimiter apply globally)
| Method | Path | Auth/Middleware | Handler |
|---|---|---|---|
| GET | /auth/ | – | inline status |
| POST | /auth/register, /auth/login | authLimiter | register, login |
| POST | /auth/refresh, /auth/logout | – | refreshTokenController, logout |
| GET/POST | /auth/verify-email | – | verifyEmail |
| POST | /auth/resend-verification | emailLimiter | resendVerificationEmail |
| GET | /auth/me | verifyToken | getCurrentUser |
| PATCH | /auth/profile | verifyToken | updateProfile |
| POST | /auth/forgot, /auth/reset | authLimiter | user.forgotPassword |
| POST | /auth/verify | authLimiter | verifyOtp |
| POST | /auth/newpassword | authLimiter | user.setNewPassword |
| GET | /services, /services/:id | verifyToken | inline |
| GET/POST | /targets | verifyToken | getTargets, createTarget |
| PATCH | /targets/:id/tech-stack | verifyToken | updateTargetTechStack |
| POST | /scanners/vulnerability | **none** | runVulnerabilityScan |
| POST | /scanners/analyze-file | **none**, multer | analyzeFile |
| GET | /audits, /audits/:id | verifyToken (detail: admin only) | listAuditLogs, getAuditLogById |
| POST | /audits/client | verifyToken | runClientAudit |
| GET/DELETE | /waf/logs | **none** | inline |
| GET | /waf/stats | **none** | inline |
| GET/POST | /waf/config | **none** | inline |
| POST | /waf/simulate | **none** | inline |
| POST | /phishing/analyze-url, /phishing/analyze-message | verifyToken, 60/15min | handlers |
| POST | /security/{website-scan,scan}, /website-security/{website-scan,scan} | verifyToken, 30/15min | scanWebsiteHandler |
| GET | /ai/status | optional auth | aiStatus |
| POST | /ai/chat, /ai/explain | optional auth (WAF body inspection skipped) | chat, explain |
| GET | /ai/recommendations | verifyToken | recommendations |
| POST | /ai/configure | verifyToken + admin role | configureAI |

Outside `/api`: `GET /` (health check) and the Socket.io events listed in §4.

## 9. Frontend and UI/UX Implementation
- **Routes** (`src/App.js`):
  - Public: `/`, `/login`, `/signup`, `/reset`, `/newpassword/:token`, `/verify-email`.
  - Protected: `/profile`, `/notifications`, `/ai-rakshak`, `/dashboard`, `/service/:id`, `/vulnerabilities`, `/phishing-detector`, `/security-audits`, `/file-scanner`, `/password-security`, `/password-lab`, `/website-security`, `/website-scanner`, `/simulation-lab`.
  - No 404 route and no lazy loading. The stale comment at `App.js:31` mentions a "bypass mode".
- **API layer:** `src/utils/api.js` is an axios instance with `withCredentials`, a 10s timeout, and a 401 refresh interceptor. The interceptor queues requests during a refresh and dispatches `auth:session_expired` if the refresh fails. `utils/axios.js` is a re-export shim used by the legacy reset flow. `FileScannerScreen` uses raw axios with its own `API_BASE`.
- **Three styling systems coexist:**
  1. Tailwind utilities with a hardcoded dark slate palette (slate-950/900/800 with cyan, blue, indigo, emerald, amber and rose accents). Used by most tool screens.
  2. daisyUI components (`btn`, `badge`, `modal`, `table`, `card`). Used by VulnerabilityScanner, VerifyEmail and the legacy modals.
  3. Custom CSS in `App.css` (`landing-*`, `auth-*`, `profile-*`, `notification-*`, `ai-*`).
- `tailwind.config.js` has an empty `theme.extend`, the daisyUI plugin and no `darkMode` setting. `animate-fade-in` is used but never defined.
- System font stack; framer-motion throughout; `prefers-reduced-motion` is respected in `App.css`. Responsive layouts use Tailwind breakpoints, the dashboard's mobile drawer and media queries.
- Icons: lucide-react is the default. Iconify Fluent and Noto icons are used on the Dashboard and in the Simulation Lab, through the `IC` map in `utils/icons.js`.
- **PDF export:** `utils/pdfGenerator.js` and `VulnerabilityScanner.jsx` both call `doc.autoTable(...)`. With jspdf 4 and autotable 5 this method may not exist (UNVERIFIED). The safer form is `autoTable(doc, …)`.

## 10. Authentication and Security
**Implemented controls:**
- Helmet CSP and strict CORS
- HttpOnly SameSite=strict cookies
- Refresh rotation with reuse detection
- bcrypt with 12 rounds
- Password policy at registration
- Rate limits
- WAF
- SSRF guard (website scanner only)
- Audit logs with metadata sanitisation
- AI prompt scrubbing
- Upload allow-list with 15MB limit and temp-file cleanup

**Critical gaps (prioritised):**
1. The reset token is returned by `/auth/forgot`, which allows account takeover with only an email address (`user.controller.ts:23-25`).
2. NoSQL injection in `setNewPassword` (`{token:{$ne:""}}`) and `verifyOtp`.
3. All `/api/waf/*` endpoints are unauthenticated: config changes, log deletion and reading traffic.
4. The WAF stores plaintext passwords from POST bodies and broadcasts them to all sockets.
5. `setNewPassword` returns the password hash.
6. `/api/scanners/*` has no auth.
7. The socket scan has an IDOR (no ownership check) and no SSRF guard on `target.host`.
8. `X-Forwarded-For` spoofing turns the client audit into an arbitrary port scanner.
9. ~~Any user can change the global AI keys.~~ Fixed 2026-11-11: admin-only, keys are env-only.
10. Hardcoded fallback JWT secrets in `util/jwt.util.ts:11,13`.
11. Email verification is bypassed at registration and never checked at login.
12. 4-digit `Math.random` OTP with no expiry or attempt limit.
13. Unescaped regexes in `waf.ts:30-33` and `auditController.ts:386`.
14. ~~The Gemini key is sent in the URL.~~ Fixed 2026-11-11: sent in the `x-goog-api-key` header.
15. Socket auth is checked only at the handshake.

## 11. Development History and Important Decisions (inferred from code; no git history)
- Started as a deliberately vulnerable MERN training app: the README, `otp_script.py`, and the "find the vulnerability" text in the reset screens. It was later rebuilt into the RAKSHAK platform with hardened auth (cookie JWT and refresh rotation), Helmet, CORS, rate limits and audit logs.
- The service catalog was trimmed from 6 to 5 tools. IDs 4, 5 and 6 (intrusion, API monitoring, encryption) were retired, and seeding deletes them. Service 2 was renamed "Phishing & Scam Detector", and 7 (Password Lab) and 8 (Website Scanner) were added. The frontend carries matching defensive overrides.
- Service detail moved from a generic socket "execution" UI to dedicated screens per serviceId. The 800ms simulated log streams were replaced by real scanners (`generateLogsForService` is now dead code).
- The AI layer went from Groq only (`groqService.ts`, now dead) to multiple providers with an offline expert engine.
- Email verification exists but is bypassed (`isEmailVerified: true`), probably for demo convenience.
- Google OAuth was probably attempted and removed: there are GOOGLE_* env vars and stray passport packages.
- A production build was made on 2026-10-15. Compiled `.js` files were last rebuilt then and match the `.ts` sources.

## 12. Completed Features
- Signup, login, logout, refresh, `/me`, profile edit.
- Dashboard with services.
- Phishing URL and message analysis.
- Client network and browser audit.
- Password analyzer and generator.
- Simulation Lab with progress tracking.
- AI chat with multiple providers and offline fallback.
- Audit logging, the audit list and notifications.
- File upload scanning for plain-text and code files.
- Targets CRUD (create, list, update tech stack).
- WAF blocking and logging.
- Website scanner SSRF validation and TLS check.

## 13. Pending / Partial Features
- Website header scanning is broken on Node 24.
- Office and PDF content scanning is broken.
- The CVE scanner uses mock service detection and invents fake fallback CVEs.
- The socket execution path uses server-local scanners, and the file-integrity monitor does nothing.
- Email verification is not enforced.
- The password-reset email flow is missing; there is no reset email.
- No WAF dashboard UI. UNVERIFIED whether one was planned.
- SecurityAuditsScreen is not linked from the UI.
- No 404 page.
- Google OAuth is not implemented.
- No tests: `App.test.js` is the stock CRA test and fails, and the backend has no test script.
- README is stale.

## 14. Known Bugs and Technical Issues

**Backend:**
- `services/websiteScanner/headerScanner.ts:75-77,175-177`: custom lookup incompatible with Node 24, so every header probe fails.
- `services/fileScanner.ts:226`: officeparser v8 returns an AST; the fix is `(await ast.to('text')).value` or the equivalent API.
- `services/fileScanner.ts:36-41`: ClamAV options are snake_case and should be camelCase. ClamAV is also re-initialised on every scan.
- `headerScanner.ts:55`: the HTTPS probe uses port 80 for `http://` URLs.
- `index.ts:49`: CORS doesn't allow PATCH, so `PATCH /auth/profile` and the tech-stack update may fail the browser preflight.
- `wafMiddleware.ts:99`: the `#`/`--` rule blocks legitimate input.
- `user.controller.ts:39-49`: the request hangs on an invalid token.
- `aiController.ts:47-115`: missing try/catch.
- `auditController.ts:491`: lookup by eventId causes a CastError and a 500.
- `waf.ts:129-151`: timeline bucket timezone mismatch.
- `aiOrchestrator.ts:82,101`: `fallbackUsed` is always false.
- ~~`cyberIntelligenceEngine.ts`: substring false positives, and the greeting topic wins ties.~~ Fixed 2026-11-11.
- `tlsScanner.ts:48-53`: wildcard match has no dot boundary.
- `scoreCalculator.ts:314-321`: TLS points ordering.
- `nvdScanner.ts:105-117`: fake CVEs; no timeout.
- `routes/auth.ts`: all auth routes share one 5-per-15-minute limiter.
- `phishing.controller.ts:703-706`: a non-string `senderInfo` causes a 500.
- 10kb body limit versus the 10000-character message limit.
- `mogoClient.ts`: seeds even when the connection fails.
- `auditLog.model.ts`: duplicate eventId index.

**Frontend:**
- `ServiceDetailScreen.jsx:665`: stray `)}      )}` artifact, as reported by the analysis. Verify it before removing.
- `SecurityAuditsScreen.jsx` is not UTF-8 (`�` at lines ~61, 76 and 456). Re-encode it before editing.
- `OtpModal.jsx`: stray `w` text node (~72), `maxlength` instead of `maxLength`, mismatched ids, unused prop, typo "Verfiy".
- `LoadingScreen.jsx:7`: `class` instead of `className`.
- `ResetPasword.jsx:41`: typo.
- `animate-fade-in` is not defined anywhere.
- Possible break in the jsPDF autotable API.
- `VulnerabilityScanner.jsx:83-86` silently shows mock data when the backend fails.
- `SuccessModal.jsx` is unused.
- The `item.badge` field is never set in the Dashboard.
- `.gitignore` has bare filenames that also match the `public/` assets.
- daisyUI is listed under devDependencies.

## 15. Coding Standards and Development Constraints
- **Backend:**
  - TypeScript strict, CommonJS, ES2016 target.
  - camelCase functions. Controller files are named `*.controller.ts` (with exceptions: `scanners.ts`, `auditController.ts`, `aiController.ts`) and models `*.model.ts`.
  - Mongoose models export `XModel` and interfaces `IX`.
  - Responses are usually `{success, ...}` or `{message, user}`. Errors are `{error, code?}` with uppercase codes such as `TOKEN_EXPIRED`, `RATE_LIMIT_EXCEEDED` and `SESSION_REVOKED`.
  - Every security-relevant action calls `recordAuditEvent` (category, status, severity, actor, requestId).
  - Input is validated by hand in controllers; there is no validation library.
  - Long section comments and banner headers are used.
  - **Edit `.ts` only**, then run `npm run build` to regenerate the `.js` siblings. Runtime uses ts-node with `preferTsExts: true`.
- **Frontend:**
  - Functional components with hooks, `.jsx` screens in `src/screens`, PascalCase names ending in `Screen`.
  - API calls go through `src/utils/api.js`; don't create new axios instances.
  - Auth state comes from `useAuth()`.
  - New tool screens should follow the Tailwind dark-slate style with framer-motion, lucide icons, and loading/error/empty states. Handle 429 and timeout errors as the phishing screen does.
- Keep the architecture as it is: route → middleware → controller → service, cookie-based JWT, the service-ID dispatch in ServiceDetailScreen, and backend seeding in `seedServices` (keep the frontend overrides in sync).
- Don't remove the intentional educational content in the Simulation Lab or the Password Lab.

## 16. Important File References
- **Backend core:**
  - `node-backend/index.ts`
  - `node-backend/routes/index.ts` (mounts)
  - `node-backend/middleware/{verifyToken,rateLimiter,fileUpload,wafMiddleware}.ts`
  - `node-backend/util/jwt.util.ts`
  - `node-backend/socket/serviceSocket.ts`
  - `node-backend/model/service.model.ts` (seeding)
- **Feature logic:**
  - `controller/auth.controller.ts`, `controller/user.controller.ts` (legacy reset)
  - `controller/phishing.controller.ts`
  - `controller/auditController.ts`
  - `controller/websiteSecurity.controller.ts` with `services/websiteScanner/*`
  - `controller/scanners.ts` with `services/fileScanner.ts` and `services/nvdScanner.ts`
  - `controller/aiController.ts` with `services/ai*.ts`, `cyberIntelligenceEngine.ts` and `knowledgeBase.ts`
  - `routes/waf.ts`
- **Frontend:**
  - `src/App.js`, `src/context/AuthContext.jsx`, `src/utils/api.js`, `src/components/ProtectedRoute.jsx`
  - `src/screens/DashboardScreen.jsx`, `src/screens/ServiceDetailScreen.jsx` (dispatcher)
  - Each tool screen listed in §6
  - `src/utils/{browserAudit,passwordAnalyzer,passwordGenerator,pdfGenerator,simulationScenarios,simProgress,icons}.js`
- **Config:** `package.json`, `node-backend/package.json`, `node-backend/tsconfig.json`, `node-backend/.env.example`, `tailwind.config.js`.

## 17. Recommended Development Roadmap
1. **Security P0:**
   - Remove the token from the `/forgot` response and email the OTP instead.
   - Sanitise or cast query inputs (express-mongo-sanitize or explicit `String()`).
   - Strip the password from responses.
   - Put auth on `/api/scanners/*` and admin-only auth on `/api/waf/*` and `/api/ai/configure`.
   - Stop storing and broadcasting request bodies in the WAF (redact sensitive fields), and scope `live-traffic-update` to admins.
   - Fail startup if the JWT secrets are missing.
2. **Broken features:**
   - Fix the header scanner lookup for Node 24 (support `opts.all`).
   - Fix officeparser text extraction.
   - Fix the ClamAV options.
   - Add PATCH to CORS.
   - Fix the hang in `setNewPassword` and the missing try/catch blocks.
   - Fix the eventId lookup.
3. **Hardening:**
   - SSRF validation and an ownership check for socket targets.
   - `trust proxy` configuration instead of trusting raw XFF.
   - Separate rate limiters per route.
   - Crypto-random 6-digit OTP with a TTL and an attempt limit.
   - Enforce email verification.
   - Hash stored refresh tokens.
   - TTL indexes on trafficlogs and auditlogs.
   - Narrow the WAF `#`/`--` rule.
4. **Data honesty:** remove the mock CVE fallbacks on both backend and frontend, or label them clearly; make service detection real or user-supplied (for example the target's techStack).
5. **UX:**
   - Link SecurityAuditsScreen.
   - Add a 404 route.
   - Re-encode SecurityAuditsScreen as UTF-8.
   - Fix OtpModal and LoadingScreen.
   - Define `animate-fade-in`.
   - Verify PDF export.
   - Consider a WAF dashboard screen.
   - Unify styling.
   - Lazy-load routes.
6. **Quality:** add tests (Jest/Supertest for the backend, RTL for the frontend), update the README, clean up dependencies and dead code, and fix `.gitignore`.

## 18. Critical Context for the Next Conversation
- Backend runs on ts-node (`preferTsExts: true`) with Node 24. Edit only `.ts` files, then `npm run build`. AI tests: `npm run test:ai` in `node-backend`.
- Frontend is CRA on port 3000, backend on port 3001, with cross-origin credentialed cookies. CORS allow-list and methods are in `index.ts`.
- The WAF runs before every `/api` route. Attack-like test payloads, and any `#` or `--`, are blocked with 403 in active mode. Account for this when testing.
- Service IDs 1, 2, 3, 7 and 8 are hardcoded in three places: backend seeding, the DashboardScreen overrides, and the ServiceDetailScreen dispatch. Keep all three in sync.
- Several insecure behaviours may be **intentional training targets**: the legacy OTP/reset flow and `otp_script.py`. Ask the user before "fixing" them.
- Never fabricate files. The authoritative file list is §5.

---

# PROJECT CONTEXT TRANSFER PROMPT

```
You are my Senior Software Architect and AI Prompt Engineer for the project "RAKSHAK" — an MCA major project: a MERN-stack (React 18 CRA + Tailwind/daisyUI/framer-motion frontend; Node/Express 4 + TypeScript (run via ts-node, Node 24) + MongoDB/Mongoose 7 + Socket.io backend) cybersecurity platform. The full project knowledge base is pasted below (sections 1–18). Treat it as the authoritative description of the codebase; anything marked UNVERIFIED must be confirmed by the coding agent before relying on it.

YOUR JOB: For every request I give (bug fix, debugging, feature improvement, UI/UX enhancement, optimization, new feature), you do NOT write the code yourself. You produce a professional, detailed, step-by-step PROMPT that I will give to an AI coding agent (e.g., Claude Code / Cursor) working directly in the repository.

BEFORE writing a prompt:
1. Restate my requirement and analyze it against the knowledge base: which module(s), files, routes, models, screens and known bugs are involved. Ask me clarifying questions if the requirement is ambiguous or conflicts with existing behavior (especially for legacy intentionally-vulnerable parts like the OTP/reset flow and otp_script.py).
2. Identify likely root causes (cite known bugs from section 14 when relevant), not just symptoms.

EVERY PROMPT YOU GENERATE MUST:
- Start with a short context block (project stack + the relevant module summary) so the agent needs no prior history.
- Instruct the agent to FIRST inspect and read the exact existing files (give exact paths from the knowledge base) and verify current behavior before modifying anything; never assume a feature/file exists without checking.
- Require root-cause analysis and a brief written plan before code changes.
- Specify exact files to modify, expected behavior, implementation requirements, and constraints:
  • Backend: edit only .ts files (compiled .js sit beside them); keep route → middleware → controller → service layering; use existing helpers (recordAuditEvent/sanitizeMetadata in services/auditService.ts, verifyToken/optionalVerifyToken, rate limiters, validateTargetUrl for any outbound URL/host); keep response shapes ({success,...} / {error, code}); add audit events for security-relevant actions.
  • Frontend: use src/utils/api.js (cookie auth, withCredentials, refresh interceptor) and useAuth(); match the dark-slate Tailwind + framer-motion + lucide style; include loading/error/empty states, 429/timeout handling, responsive layout.
  • Keep service IDs 1,2,3,7,8 consistent across model/service.model.ts seeding, DashboardScreen.jsx overrides and ServiceDetailScreen.jsx dispatch.
  • Remember the WAF (middleware/wafMiddleware.ts) inspects all /api traffic and the CORS methods list in index.ts.
- Forbid unnecessary refactors, renames, dependency changes, or touching unrelated files; preserve existing functionality and APIs unless the change requires otherwise (and then state migration impact).
- Include security requirements (input validation/type-checking, no NoSQL injection, no secret leakage in responses/logs, authz/ownership checks, SSRF safety), performance and maintainability considerations.
- Include explicit error-handling and validation instructions.
- Include a testing section: exact manual test steps (curl/Postman requests with bodies, UI click-paths), edge cases, negative/security tests, and REGRESSION checks for adjacent features; run `npx tsc --noEmit` in node-backend and `npm run build` at the root to confirm compilation; mention adding automated tests where reasonable.
- End with a required deliverable summary from the agent: root cause, files changed, what was verified, anything left unresolved.

OUTPUT FORMAT for each response: (1) Requirement analysis & assumptions, (2) Root-cause hypotheses, (3) The ready-to-copy coding-agent prompt in a single code block, (4) Optional follow-up prompts if the task should be split into phases.

Focus on production-quality, secure, performant, maintainable code and responsive UI/UX. Never invent files, endpoints, fields, or libraries that the knowledge base does not list — if something is needed but unknown, instruct the agent to discover it first.

=== PROJECT KNOWLEDGE BASE ===
[Paste sections 1–18 of PROJECT_CONTEXT.md here]
```
