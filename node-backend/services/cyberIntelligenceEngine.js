"use strict";
/**
 * AI RAKSHAK - Cyber Intelligence Knowledge & NLP Inference Engine
 * Provides comprehensive, expert-level cybersecurity guidance even when
 * external LLM providers (Groq / Gemini / OpenAI) are not configured or offline.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.queryCyberIntelligence = exports.CYBER_TOPICS = void 0;
exports.CYBER_TOPICS = [
    // ── 1. GREETINGS & CAPABILITIES ───────────────────────────────────────────
    {
        id: 'greeting',
        category: 'general',
        title: 'Welcome to AI RAKSHAK',
        keywords: ['hello', 'hi', 'hey', 'greetings', 'who are you', 'what are you', 'what can you do', 'help', 'capabilities', 'start'],
        patterns: [/\b(hello|hi|hey|greetings|who are you|what can you do|help me|capabilities)\b/i],
        summary: "Hello! I am **AI RAKSHAK**, your specialized Cybersecurity & Threat Intelligence assistant. I'm here to provide educational guidance, explain technical findings, and help you defend against modern digital threats.",
        steps: [
            '**Phishing & Scam Analysis**: Identify deceitful emails, suspicious URLs, SMS smishing, and social engineering tricks.',
            '**Account & Identity Hardening**: Learn password entropy, password managers, and multi-factor authentication (MFA/2FA).',
            '**Website & API Security**: Understand HTTPS/TLS, security headers (CSP, HSTS), and OWASP Top 10 vulnerabilities (SQLi, XSS, CSRF).',
            '**File & Malware Defense**: Learn how to handle suspicious attachments, ransomware prevention, and malware containment.',
            '**Incident Response**: Immediate containment steps if compromised, plus official reporting via **1930** and **cybercrime.gov.in**.',
            '**Rakshak Security Suite**: Guidance on using our integrated scanners, simulation lab, and Web Application Firewall (WAF).'
        ],
    },
    // ── 2. RAKSHAK PLATFORM MODULES ───────────────────────────────────────────
    {
        id: 'rakshak-overview',
        category: 'rakshak',
        title: 'Rakshak Security Platform Overview',
        keywords: ['rakshak', 'platform', 'tools', 'services', 'features', 'scanners', 'suite'],
        patterns: [/\b(rakshak (tools|features|platform|services|suite)|how to use rakshak)\b/i],
        summary: '**Rakshak** is a comprehensive cybersecurity operations platform combining automated scanners, client-side security labs, simulated defense drills, and real-time WAF telemetry.',
        steps: [
            '**Phishing & Scam Detector**: Heuristic engine inspecting URLs, emails, and SMS for spoofing, deceptive domains, and urgency markers.',
            '**Website Security Scanner**: Inspects HTTPS configuration, TLS certificates, and essential HTTP response headers (CSP, HSTS, X-Frame-Options).',
            '**File Malware Scanner**: Multi-stage file analysis checking signatures, hashes, and behavioral anomalies.',
            '**Password Security Lab**: Client-side password entropy, pattern vulnerability checks, and cryptographically secure passphrase generation.',
            '**Simulation Lab**: Interactive scenarios covering Phishing, SQL Injection, and Defense mechanisms.',
            '**Web Application Firewall (WAF)**: Live threat inspection, regex signature matching, and automated attack blocking.'
        ],
        rakshakTool: {
            name: 'Security Dashboard',
            path: '/dashboard',
            description: 'Access all integrated Rakshak security services and telemetry.'
        }
    },
    {
        id: 'rakshak-phishing-tool',
        category: 'rakshak',
        title: 'Using Rakshak Phishing Detector',
        keywords: ['phishing detector', 'check link', 'check url', 'check email', 'check sms', 'scan link'],
        patterns: [/\b(phishing detector|how to (scan|check) (link|url|email|message))\b/i],
        summary: "Rakshak's **Phishing & Scam Detector** allows you to paste URLs, raw email content, or SMS messages to assess deceptive markers, typo-squatting, credential harvesting patterns, and homograph tricks.",
        steps: [
            'Navigate to **Phishing Detector** from the dashboard or sidebar.',
            'Select the input mode: **URL Analysis**, **Email Inspection**, or **SMS Message**.',
            'Paste the suspicious content and initiate the heuristic scan.',
            'Review the risk score, flagged indicators (e.g. IP-based host, deceptive TLD, urgent payment calls), and verified remediation advice.'
        ],
        rakshakTool: {
            name: 'Phishing & Scam Detector',
            path: '/phishing-detector',
            description: 'Analyze suspicious URLs, emails, and SMS messages safely.'
        }
    },
    {
        id: 'rakshak-website-scanner',
        category: 'rakshak',
        title: 'Using Rakshak Website Security Scanner',
        keywords: ['website scanner', 'scan website', 'website security', 'check domain', 'tls check'],
        patterns: [/\b(website (scanner|security)|scan (website|domain|host))\b/i],
        summary: "The **Website Security Scanner** evaluates external websites for essential transport security and browser defense headers.",
        steps: [
            'Open **Website Security Scanner** from the Dashboard or navigation menu.',
            'Enter the target domain or full URL (e.g., `https://example.com`).',
            'Inspect TLS/SSL certificate health: validity dates, issuer, protocol versions (TLS 1.2/1.3).',
            'Check browser hardening headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `X-Frame-Options`.'
        ],
        rakshakTool: {
            name: 'Website Security Scanner',
            path: '/website-security',
            description: 'Scan HTTPS, certificates, and HTTP security headers.'
        }
    },
    {
        id: 'rakshak-password-lab',
        category: 'rakshak',
        title: 'Using Rakshak Password Security Lab',
        keywords: ['password lab', 'password tool', 'generate password', 'password strength', 'entropy'],
        patterns: [/\b(password (lab|tool|generator|strength)|check (my )?password)\b/i],
        summary: "The **Password Security Lab** operates strictly inside your browser: no passwords or secret inputs are ever transmitted over the network.",
        steps: [
            'Evaluate password strength using Shannon entropy and zxcvbn pattern matching.',
            'Detect common pitfalls: sequential patterns (`1234`), keyboard walks (`qwerty`), dictionary words, and leaked credential lists.',
            'Generate cryptographically resilient multi-word passphrases or randomized symbol-dense keys.'
        ],
        rakshakTool: {
            name: 'Password Security Lab',
            path: '/password-security',
            description: 'Privately test password strength and generate uncrackable passphrases.'
        }
    },
    {
        id: 'rakshak-file-scanner',
        category: 'rakshak',
        title: 'Using Rakshak File Scanner',
        keywords: ['file scanner', 'scan file', 'upload file', 'check virus', 'malware scanner'],
        patterns: [/\b(file scanner|scan (a )?file|check (file|document|pdf) for virus)\b/i],
        summary: "The **File Scanner** processes uploaded documents, archives, and binaries using antivirus signature matching and file integrity checks.",
        steps: [
            'Navigate to **File Scanner**.',
            'Upload the suspicious file (PDF, Office document, ZIP archive, or executable).',
            'The backend scans for known malware signatures, embedded malicious macros, and suspicious payload structures.',
            'Review the verdict, SHA-256 hash, and safe handling instructions.'
        ],
        rakshakTool: {
            name: 'File Scanner',
            path: '/file-scanner',
            description: 'Scan files for malware signatures and malicious macros.'
        }
    },
    {
        id: 'rakshak-simulation-lab',
        category: 'rakshak',
        title: 'Using Rakshak Simulation Lab',
        keywords: ['simulation lab', 'simulate attack', 'security lab', 'interactive quiz', 'practice lab'],
        patterns: [/\b(simulation lab|security simulation|practice (attack|defense))\b/i],
        summary: "The **Simulation Lab** provides hands-on, sandboxed security exercises to experience realistic attacks and defenses without real-world risk.",
        steps: [
            'Select a scenario: **Phishing Simulation**, **SQL Injection Defense**, or **Defense Architecture**.',
            'Analyze attack artifacts, dissect malicious payloads, and practice safe response decisions.',
            'Reinforce defensive thinking with instant feedback and score tracking.'
        ],
        rakshakTool: {
            name: 'Simulation Lab',
            path: '/simulation-lab',
            description: 'Sandboxed interactive exercises for cybersecurity learning.'
        }
    },
    // ── 3. PHISHING & SOCIAL ENGINEERING ─────────────────────────────────────
    {
        id: 'phishing-general',
        category: 'phishing',
        title: 'Identifying & Defending Against Phishing Scams',
        keywords: ['phishing', 'smishing', 'vishing', 'scam', 'fake message', 'fake email', 'suspicious link', 'spoofing', 'impersonation'],
        patterns: [/\b(phishing|smishing|vishing|fake (email|message|sms)|scam (link|email|call)|suspicious (email|link|text))\b/i],
        summary: "**Phishing** is a social engineering attack where cybercriminals impersonate legitimate organizations (banks, government, employers, tech services) to steal credentials, OTPs, or financial assets.",
        risks: [
            'Credential harvesting via cloned login portals.',
            'Session hijacking via OTP theft.',
            'Malware or spyware installation via unsolicited attachments.'
        ],
        steps: [
            '**Inspect the Sender Domain**: Look closely at the exact email address or link URL. Attackers use lookalikes (e.g., `paypal-security-alert.com` instead of `paypal.com`).',
            '**Beware of Artificial Urgency**: Messages claiming your account will be deleted in 2 hours or threatening legal action are designed to trigger panic.',
            '**Never Share OTPs or Passwords**: Legitimate banks and support teams will never ask for your password, PIN, or SMS OTP.',
            '**Verify Independently**: Rather than clicking links in emails or texts, open a fresh browser tab and visit the official website directly or call their verified number.',
            '**Scan Suspicious Links**: Run the URL through **Rakshak Phishing & Scam Detector** before interacting.'
        ],
        rakshakTool: {
            name: 'Phishing Detector',
            path: '/phishing-detector',
            description: 'Analyze suspicious URLs, emails, and SMS messages.'
        }
    },
    {
        id: 'suspicious-link-clicked',
        category: 'phishing',
        title: 'What to Do After Clicking a Suspicious Link',
        keywords: ['clicked link', 'clicked a suspicious link', 'clicked phishing', 'clicked scam', 'accidentally clicked'],
        patterns: [/\b(clicked (a )?(suspicious|phishing|bad|wrong) link|what (to do|if) (i )?clicked)\b/i],
        summary: "If you clicked a suspicious link, stay calm. Immediate tactical containment prevents the attacker from escalating access.",
        steps: [
            '**1. Disconnect Network**: Immediately disconnect Wi-Fi or unplug ethernet if a file started downloading or your browser behaved erratically.',
            '**2. Do NOT Submit Any Data**: If a webpage opened asking for logins, card numbers, or OTPs, close the tab immediately without entering any keystrokes.',
            '**3. Change Passwords Immediately**: From a *clean device*, change the password of any account associated with that service and terminate all other active sessions.',
            '**4. Revoke Active Sessions & Check 2FA**: Enable an authenticator app (TOTP) and review recent logins or authorized apps.',
            '**5. Scan Your Device**: Run a full system antivirus scan with Windows Defender or ClamAV to verify no malware or dropper was executed.'
        ],
        rakshakTool: {
            name: 'Phishing Detector',
            path: '/phishing-detector',
            description: 'Paste the clicked link to evaluate the threat payload.'
        }
    },
    // ── 4. PASSWORDS, AUTHENTICATION & MFA ────────────────────────────────────
    {
        id: 'passwords-mfa',
        category: 'passwords',
        title: 'Account Hardening, Strong Passwords & Multi-Factor Authentication',
        keywords: ['password', 'passphrase', 'mfa', '2fa', 'two-factor', 'multifactor', 'authenticator', 'credential stuffing', 'brute force', 'totp', 'passkey'],
        patterns: [/\b(password (security|manager|strength)|(enable|how does) (mfa|2fa)|multi[- ]factor|authenticator app|secure (my )?account)\b/i],
        summary: "Account takeovers are predominantly driven by password reuse and lack of multi-factor authentication. Strong passphrase architecture and hardware/app-based 2FA provide near-impenetrable identity protection.",
        risks: [
            'Credential stuffing: When one website leaks your password, bots test it across banking, email, and social accounts.',
            'Brute force & dictionary attacks against short or predictable passwords.',
            'SIM swapping: Bypassing SMS-based 2FA by porting your phone number.'
        ],
        steps: [
            '**Use Passphrases Over Complex Short Passwords**: A 4-word random passphrase (e.g. `correct-horse-battery-staple`) has far greater entropy than `P@ss1` and is easier to remember.',
            '**Never Reuse Passwords**: Every single online account must have a distinct, unique secret.',
            '**Adopt a Password Manager**: Tools like Bitwarden, 1Password, or KeePass generate, store, and auto-fill strong credentials with end-to-end encryption.',
            '**Upgrade to App-Based MFA or Passkeys**: Prefer Time-based One-Time Passwords (TOTP apps like Aegis, Google Authenticator) or FIDO2/Passkeys over SMS OTPs.',
            '**Store Recovery Codes Offline**: Keep backup 2FA recovery codes printed or stored in a secure physical location.'
        ],
        rakshakTool: {
            name: 'Password Security Lab',
            path: '/password-security',
            description: 'Test password entropy and generate resilient secrets.'
        }
    },
    // ── 5. WEB & APPLICATION SECURITY (OWASP TOP 10) ─────────────────────────
    {
        id: 'owasp-sqli',
        category: 'web-security',
        title: 'SQL Injection (SQLi) Vulnerability & Prevention',
        keywords: ['sql injection', 'sqli', 'database injection', 'union select', 'or 1=1', 'sql query'],
        patterns: [/\b(sql injection|sqli|prevent sqli|database injection|sql attack)\b/i],
        summary: "**SQL Injection (SQLi)** occurs when untrusted user input is directly concatenated into a dynamic SQL query, allowing an attacker to manipulate queries, bypass authentication, extract sensitive tables, or delete data.",
        risks: [
            'Authentication bypass (e.g. `\' OR 1=1 --`).',
            'Full database exfiltration via `UNION SELECT`.',
            'Database tampering, deletion, or administrative compromise.'
        ],
        steps: [
            '**Parameterized Queries (Prepared Statements)**: Always use parameterized queries or trusted ORMs (e.g. Mongoose, Prisma, TypeORM). Never build SQL strings with variable concatenation.',
            '**Input Validation & Type Casting**: Enforce strict allow-lists and cast numerical IDs to integers before querying.',
            '**Principle of Least Privilege**: Ensure the database user account only has privileges required for its runtime tasks (e.g. deny `DROP TABLE` or `GRANT` to the web app).',
            '**Deploy a Web Application Firewall**: Use Rakshak WAF to detect and block SQLi signature patterns in real-time.'
        ],
        rakshakTool: {
            name: 'Simulation Lab - SQLi Exercise',
            path: '/simulation-lab',
            description: 'Explore live SQL injection patterns and defense coding.'
        }
    },
    {
        id: 'owasp-xss',
        category: 'web-security',
        title: 'Cross-Site Scripting (XSS) Prevention & Defense',
        keywords: ['xss', 'cross-site scripting', 'stored xss', 'reflected xss', 'dom xss', 'script injection'],
        patterns: [/\b(xss|cross[- ]site scripting|script injection|prevent xss)\b/i],
        summary: "**Cross-Site Scripting (XSS)** allows attackers to execute arbitrary malicious JavaScript in a victim's browser, leading to session cookie theft, keylogging, or defacement.",
        risks: [
            'Stealing sensitive session tokens stored in `localStorage`.',
            'Impersonating the victim to perform unauthorized financial or administrative actions.',
            'Phishing popups injected directly into trusted domains.'
        ],
        steps: [
            '**Context-Aware Output Encoding**: HTML-encode all user input before rendering it in HTML body, attributes, or script contexts.',
            '**Use Modern Frameworks**: Frameworks like React and Vue automatically escape variables rendered in JSX templates.',
            '**Store Tokens in HttpOnly Cookies**: Never store sensitive JWTs or session tokens in `localStorage` or `sessionStorage` where JavaScript can access them.',
            '**Enforce Strict Content Security Policy (CSP)**: Disallow `unsafe-inline` scripts and restrict script loading strictly to trusted origins.'
        ],
        rakshakTool: {
            name: 'Website Security Scanner',
            path: '/website-security',
            description: 'Verify if your website enforces a Content-Security-Policy (CSP).'
        }
    },
    {
        id: 'web-security-headers',
        category: 'web-security',
        title: 'Essential HTTP Security Headers',
        keywords: ['security headers', 'csp', 'hsts', 'x-frame-options', 'content-security-policy', 'headers', 'strict-transport-security'],
        patterns: [/\b(security headers?|csp|hsts|x-frame-options|content-security-policy)\b/i],
        summary: "HTTP Security Headers are directives sent by the web server to the client browser that enforce strict security boundaries and disable legacy browser vulnerabilities.",
        steps: [
            '**Content-Security-Policy (CSP)**: Restricts the resources (scripts, styles, images) that browsers are permitted to load for a page, neutralizing XSS attacks.',
            '**Strict-Transport-Security (HSTS)**: Instructs browsers to communicate exclusively over HTTPS, preventing SSL-stripping man-in-the-middle attacks (`max-age=31536000; includeSubDomains; preload`).',
            '**X-Frame-Options**: Prevents clickjacking by forbidding third-party sites from framing your application (`DENY` or `SAMEORIGIN`).',
            '**X-Content-Type-Options**: Prevents MIME-sniffing (`nosniff`).',
            '**Referrer-Policy**: Limits leakage of path and query secrets in HTTP referrer headers (`strict-origin-when-cross-origin`).'
        ],
        rakshakTool: {
            name: 'Website Security Scanner',
            path: '/website-security',
            description: 'Audit any domain for presence and correctness of security headers.'
        }
    },
    {
        id: 'https-tls-certs',
        category: 'web-security',
        title: 'HTTPS, TLS Encryption & Certificate Verification',
        keywords: ['https', 'tls', 'ssl', 'certificate', 'tls 1.3', 'encryption in transit', 'padlock'],
        patterns: [/\b(https|tls|ssl|certificate validity|tls 1\.[23]|encryption in transit)\b/i],
        summary: "**HTTPS** combines HTTP with the Transport Layer Security (TLS) protocol to encrypt communications between the user's browser and the web server, ensuring confidentiality, integrity, and authenticity.",
        steps: [
            '**Confidentiality**: Encrypts requests and responses so eavesdroppers on public networks or ISPs cannot view passwords, credit cards, or private data.',
            '**Integrity**: Uses message authentication codes to ensure packets are not modified or tampered with in transit.',
            '**Authentication**: Digital certificates issued by trusted Certificate Authorities (CAs) prove the server genuinely belongs to the domain.',
            '**Protocol Version**: Always enforce **TLS 1.2** or **TLS 1.3** and disable deprecated SSL 2.0/3.0 and TLS 1.0/1.1.'
        ],
        rakshakTool: {
            name: 'Website Security Scanner',
            path: '/website-security',
            description: 'Check certificate issuer, expiration dates, and TLS protocol support.'
        }
    },
    // ── 6. NETWORK & WI-FI HARDENING ──────────────────────────────────────────
    {
        id: 'network-wifi',
        category: 'network',
        title: 'Securing Home Wi-Fi & Public Network Protection',
        keywords: ['wifi', 'wi-fi', 'router', 'public wifi', 'wpa3', 'wpa2', 'network security', 'vpn', 'man in the middle'],
        patterns: [/\b(wi[- ]?fi|router security|public wi[- ]?fi|secure (my )?network|wpa[23]|vpn)\b/i],
        summary: "Home routers are the primary perimeter gateway for your devices. Default router passwords and weak encryption make networks vulnerable to intruder eavesdropping, botnet recruitment, and DNS hijacking.",
        steps: [
            '**Change Default Admin Passwords**: Never keep the factory-set `admin/admin` or `admin/password` login for your router management page (usually `192.168.1.1`).',
            '**Enforce WPA3 or WPA2-AES**: Choose WPA3-Personal or WPA2-PSK (AES). Disable legacy WEP and WPA-TKIP.',
            '**Disable WPS & UPnP**: Wi-Fi Protected Setup (WPS) can be brute-forced within hours; Universal Plug and Play (UPnP) can open unauthorized firewall holes.',
            '**Create a Separate Guest/IoT Network**: Segregate smart TVs, cameras, and smart home gadgets from your personal laptops and phones.',
            '**Use a Trusted VPN on Public Wi-Fi**: When connecting to coffee shops, airports, or hotels, always route your traffic through an encrypted VPN tunnel.'
        ]
    },
    {
        id: 'firewalls-ports',
        category: 'network',
        title: 'Firewalls, Port Scanning & Network Defense',
        keywords: ['firewall', 'port', 'port scan', 'ddos', 'open ports', 'nmap', 'packet filtering'],
        patterns: [/\b(firewall|what is a firewall|open ports?|port scan|ddos|packet filter)\b/i],
        summary: "A **Firewall** is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules, establishing a barrier between a trusted internal network and untrusted external traffic.",
        steps: [
            '**Packet Filtering**: Inspects packet headers (source IP, destination IP, port number, protocol) to permit or deny traffic.',
            '**Stateful Inspection**: Tracks active connections and ensures incoming packets belong to established, recognized sessions.',
            '**Web Application Firewall (WAF)**: Operates at Layer 7 (Application) to inspect HTTP/S payloads for web attack signatures like SQLi, XSS, and path traversal.',
            '**Close Unnecessary Ports**: Never expose sensitive administration ports (e.g., Port 22 SSH, Port 3389 RDP, Port 445 SMB, Port 27017 MongoDB) directly to the public internet.'
        ]
    },
    // ── 7. MALWARE, RANSOMWARE & FILE THREATS ──────────────────────────────────
    {
        id: 'malware-ransomware',
        category: 'malware',
        title: 'Ransomware, Trojans & Malware Defense Strategies',
        keywords: ['ransomware', 'malware', 'trojan', 'virus', 'spyware', 'keylogger', 'worm', 'zero day', 'antivirus'],
        patterns: [/\b(ransomware|malware|trojan|virus|spyware|keylogger|zero[- ]day|ransom)\b/i],
        summary: "**Malware** refers to any malicious software designed to harm, exploit, or gain unauthorized access to computer systems. **Ransomware** encrypts the victim's files and demands payment for the decryption key.",
        risks: [
            'Irreversible loss of personal, academic, or corporate data.',
            'Credential theft via background keyloggers.',
            'Device hostage situations and extortion.'
        ],
        steps: [
            '**Follow the 3-2-1 Backup Rule**: Maintain **3** copies of critical data on **2** different media types, with **1** copy stored offsite or on an air-gapped disconnected drive.',
            '**Never Pay the Ransom**: Paying does not guarantee file recovery and actively funds criminal organizations.',
            '**Keep Operating Systems & Software Patched**: Most ransomware utilizes known vulnerabilities (like EternalBlue) that have available security patches.',
            '**Avoid Unknown Executables & Macro Documents**: Treat `.exe`, `.vbs`, `.scr`, and macro-enabled Office files (`.docm`, `.xlsm`) with extreme caution.',
            '**Scan Suspicious Downloads**: Inspect files with **Rakshak File Scanner** prior to running or extracting.'
        ],
        rakshakTool: {
            name: 'File Scanner',
            path: '/file-scanner',
            description: 'Upload files for antivirus signature and anomaly checks.'
        }
    },
    // ── 8. INCIDENT RESPONSE & CYBERCRIME REPORTING ────────────────────────────
    {
        id: 'incident-response',
        category: 'incident',
        title: 'Incident Response: What to Do If You Have Been Hacked',
        keywords: ['hacked', 'compromised', 'account hacked', 'cybercrime', 'report fraud', '1930', 'stolen account', 'financial fraud', 'cert-in'],
        patterns: [/\b(i (am|have been|got) hacked|account (is )?hacked|money (stolen|deducted)|report (cybercrime|fraud|scam)|1930|cert-in)\b/i],
        summary: "If you suspect an active compromise or financial fraud, taking fast, structured action within the first 'Golden Hours' can freeze fraudulent transactions and recover control.",
        steps: [
            '**1. Immediate Financial Freeze (India 1930 Helpline)**: For financial fraud, call the National Cyber Crime Helpline **1930** immediately. Dialing within 2-3 hours enables law enforcement to freeze money in transit across intermediary bank nodes.',
            '**2. Register on National Cyber Crime Portal**: File a detailed complaint with transaction IDs and screenshots at **[cybercrime.gov.in](https://cybercrime.gov.in)**.',
            '**3. Disconnect & Isolate Infected Systems**: Disconnect Ethernet and Wi-Fi to stop lateral spread across your home or organization network.',
            '**4. Force Session Logout & Reset Passwords**: From an independent, clean device (such as your phone), sign into your primary email and cloud accounts, click **"Sign out of all sessions"**, and update credentials.',
            '**5. Report to CERT-In**: For enterprise, server, or application security breaches in India, report incident telemetry to **CERT-In** (`incident@cert-in.org.in`).'
        ]
    },
    // ── 9. DEVSECOPS & SECURE CODING ──────────────────────────────────────────
    {
        id: 'secure-coding',
        category: 'devsecops',
        title: 'Secure Development & Application Hardening',
        keywords: ['secure coding', 'devsecops', 'input validation', 'sanitize', 'secrets management', 'api security', 'jwt security'],
        patterns: [/\b(secure coding|devsecops|input validation|jwt (security|best practices)|api security|secrets management)\b/i],
        summary: "Security must be baked into the software development lifecycle from architecture to deployment (Shift-Left Security), rather than bolted on as an afterthought.",
        steps: [
            '**Never Commit Secrets to Version Control**: Store API keys, database credentials, and JWT secrets in `.env` files and add `.env` to `.gitignore`. Use secret scanning tools (e.g. GitGuardian).',
            '**Validate & Sanitize All Input**: Treat all client data as hostile. Use schema validation libraries (e.g. Zod, Joi) on the server side.',
            '**Use Secure Cookie Flags**: For web sessions, always configure `httpOnly: true`, `secure: true`, and `sameSite: "strict"` or `"lax"`.',
            '**Implement Rate Limiting**: Guard authentication endpoints (`/login`, `/register`, `/reset`) against brute force with express-rate-limit or Redis token buckets.',
            '**Monitor Dependency Vulnerabilities**: Regularly run `npm audit` or use Snyk to detect known CVEs in third-party libraries.'
        ]
    }
];
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** Whole-word / whole-phrase keyword test, so "hi" no longer matches inside "phishing". */
const keywordMatchers = new Map();
const hasKeyword = (text, keyword) => {
    let re = keywordMatchers.get(keyword);
    if (!re) {
        re = new RegExp(`(^|[^a-z0-9])${escapeRegExp(keyword.toLowerCase())}($|[^a-z0-9])`, 'i');
        keywordMatchers.set(keyword, re);
    }
    return re.test(text);
};
const scoreTopic = (topic, normalized) => {
    let score = 0;
    for (const pattern of topic.patterns) {
        if (pattern.test(normalized))
            score += 8;
    }
    for (const kw of topic.keywords) {
        if (hasKeyword(normalized, kw))
            score += 3;
    }
    return score;
};
const GREETING_REPLY = [
    "Hello! I'm **AI RAKSHAK**, your cybersecurity assistant.",
    '',
    'I can help you check whether a message or link looks like a scam, secure your passwords and accounts, understand website security, deal with suspicious files, or decide what to do after a cyber incident. What would you like to know?',
].join('\n');
/**
 * Intelligent Matcher & Synthesizer
 */
const queryCyberIntelligence = (question, _context = '') => {
    const normalized = question.toLowerCase().trim();
    const scored = exports.CYBER_TOPICS.map((topic) => ({ topic, score: scoreTopic(topic, normalized) }))
        .filter((entry) => entry.score > 0)
        .sort((a, b) => b.score - a.score);
    // A greeting word ("hi", "help me") should not hide a real security topic in the same question.
    const best = scored.find((entry) => entry.topic.id !== 'greeting' && entry.score >= 3) || scored[0];
    if (best && best.score >= 3) {
        const topic = best.topic;
        if (topic.id === 'greeting') {
            return { answer: GREETING_REPLY, matchedTopic: topic, confidence: best.score };
        }
        const sections = [topic.summary];
        if (topic.risks && topic.risks.length > 0) {
            sections.push(`**Warning signs and risks:**\n${topic.risks.map((risk) => `- ${risk}`).join('\n')}`);
        }
        if (topic.steps && topic.steps.length > 0) {
            sections.push(`**What to do:**\n${topic.steps.map((step, idx) => `${idx + 1}. ${step}`).join('\n')}`);
        }
        if (topic.rakshakTool) {
            sections.push(`**Tip:** You can check this with **${topic.rakshakTool.name}** in Rakshak. ${topic.rakshakTool.description}`);
        }
        return { answer: sections.join('\n\n'), matchedTopic: topic, confidence: best.score };
    }
    return { answer: synthesizeGeneralGuidance(), confidence: 1 };
};
exports.queryCyberIntelligence = queryCyberIntelligence;
/** Reply for questions the offline engine has no specific guidance for. */
const synthesizeGeneralGuidance = () => [
    "I don't have specific guidance on that right now. I specialise in cybersecurity, so I can help with things like:",
    '',
    '- Checking whether an email, SMS or link is a scam',
    '- Creating strong passwords and turning on two-factor authentication',
    '- Understanding website security (HTTPS, SQL injection, XSS)',
    '- Handling suspicious files, malware or ransomware',
    '- What to do after fraud or an account compromise',
    '',
    'Try rephrasing your question around one of these topics.',
].join('\n');
