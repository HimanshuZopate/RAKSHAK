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
exports.scanFile = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const clamscan_1 = __importDefault(require("clamscan"));
const officeparser_1 = require("officeparser");
// ── Engine A: ClamAV Signature Scan ───────────────────────────────────────────
/**
 * Runs the file through ClamAV to detect known malware signatures,
 * viruses, and malicious Office macros.
 *
 * Gracefully degrades to an INFO finding if ClamAV is not installed.
 */
function runSignatureScan(filePath) {
    return __awaiter(this, void 0, void 0, function* () {
        const findings = [];
        try {
            const clamscan = yield new clamscan_1.default().init({
                remove_infected: false,
                debug_mode: false,
                scan_log: null,
                preference: 'clamscan',
            });
            const { isInfected, viruses } = yield clamscan.scanFile(filePath);
            if (isInfected && viruses && viruses.length > 0) {
                viruses.forEach((virusName) => {
                    findings.push({
                        engine: 'ClamAV',
                        category: 'Malware Signature',
                        detail: `ClamAV detected: ${virusName}`,
                        severity: 'CRITICAL',
                    });
                });
            }
        }
        catch (err) {
            console.warn('[FileScanner] ClamAV signature scan unavailable:', err.message);
            findings.push({
                engine: 'ClamAV',
                category: 'Engine Status',
                detail: 'ClamAV engine unavailable on this system — signature scan skipped. Install ClamAV for full malware detection.',
                severity: 'INFO',
            });
        }
        return findings;
    });
}
// ── Engine B: Static Analysis Patterns ────────────────────────────────────────
/**
 * Regex rules applied against extracted raw text.
 * Each rule produces at most one finding (de-duplicated by rule name).
 */
const STATIC_RULES = [
    // ─── Dangerous Code Patterns ───────────────────────────────────────────────
    {
        name: 'eval_usage',
        regex: /\beval\s*\(/gi,
        category: 'Dangerous Code Pattern',
        severity: 'HIGH',
        describe: (m) => `Potentially dangerous \`eval()\` call found: "${m.trim()}"`,
    },
    {
        name: 'exec_usage',
        regex: /\bexec\s*\(/gi,
        category: 'Dangerous Code Pattern',
        severity: 'HIGH',
        describe: (m) => `Shell execution function \`exec()\` found: "${m.trim()}"`,
    },
    {
        name: 'system_call',
        regex: /\bsystem\s*\(/gi,
        category: 'Dangerous Code Pattern',
        severity: 'HIGH',
        describe: (m) => `System call \`system()\` found: "${m.trim()}"`,
    },
    {
        name: 'base64_decode',
        regex: /base64_decode\s*\(/gi,
        category: 'Obfuscation Technique',
        severity: 'HIGH',
        describe: (m) => `Base64 decode obfuscation pattern found: "${m.trim()}"`,
    },
    {
        name: 'wscript_shell',
        regex: /WScript\.Shell/gi,
        category: 'Dangerous Code Pattern',
        severity: 'CRITICAL',
        describe: (m) => `Windows scripting host shell invocation found: "${m.trim()}"`,
    },
    {
        name: 'powershell_encoded',
        regex: /powershell[^\n]{0,30}-[Ee]nc/gi,
        category: 'Obfuscation Technique',
        severity: 'CRITICAL',
        describe: (m) => `PowerShell encoded command detected (common dropper technique): "${m.trim().slice(0, 80)}"`,
    },
    {
        name: 'cmd_exec',
        regex: /cmd\.exe|\/c\s+[a-z]/gi,
        category: 'Dangerous Code Pattern',
        severity: 'HIGH',
        describe: (m) => `Command-line shell invocation pattern found: "${m.trim()}"`,
    },
    {
        name: 'python_exec',
        regex: /\bos\.system\s*\(|subprocess\.(call|run|Popen)\s*\(/g,
        category: 'Dangerous Code Pattern',
        severity: 'HIGH',
        describe: (m) => `Python shell execution found: "${m.trim()}"`,
    },
    {
        name: 'java_runtime',
        regex: /Runtime\.getRuntime\(\)\.exec\s*\(/gi,
        category: 'Dangerous Code Pattern',
        severity: 'HIGH',
        describe: (m) => `Java Runtime shell execution found: "${m.trim()}"`,
    },
    {
        name: 'vba_macro',
        regex: /\bSub\s+Auto(?:Open|Exec|Close)\b|\bSub\s+Document_Open\b/gi,
        category: 'Malicious Macro',
        severity: 'CRITICAL',
        describe: (m) => `Auto-executing VBA macro found: "${m.trim()}" — common in Office malware droppers`,
    },
    // ─── Suspicious URLs & IPs ─────────────────────────────────────────────────
    {
        name: 'http_url',
        regex: /https?:\/\/[^\s"'<>\]]{4,}/gi,
        category: 'External URL',
        severity: 'LOW',
        describe: (m) => `External URL found: "${m.trim().slice(0, 120)}"`,
    },
    {
        name: 'private_ip',
        regex: /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g,
        category: 'Hardcoded Private IP',
        severity: 'MEDIUM',
        describe: (m) => `Hardcoded private IP address found: "${m.trim()}"`,
    },
    {
        name: 'public_ip',
        regex: /\b(?!10\.|127\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g,
        category: 'Hardcoded Public IP',
        severity: 'MEDIUM',
        describe: (m) => `Hardcoded public IP address found: "${m.trim()}"`,
    },
    // ─── Secrets & Credentials ─────────────────────────────────────────────────
    {
        name: 'aws_access_key',
        regex: /\b(?:AKIA|ASIA|AROA)[0-9A-Z]{16}\b/g,
        category: 'Exposed Credential',
        severity: 'CRITICAL',
        describe: (m) => `AWS Access Key ID pattern detected: "${m.trim()}"`,
    },
    {
        name: 'private_key_header',
        regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi,
        category: 'Exposed Private Key',
        severity: 'CRITICAL',
        describe: (m) => `Private key material found in file: "${m.trim()}"`,
    },
    {
        name: 'generic_password',
        regex: /(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[=:]\s*['"]?[^\s'"]{6,}/gi,
        category: 'Hardcoded Secret',
        severity: 'HIGH',
        describe: (m) => `Hardcoded credential/secret pattern found: "${m.trim().slice(0, 80)}"`,
    },
    {
        name: 'github_token',
        regex: /ghp_[A-Za-z0-9]{36}/g,
        category: 'Exposed Credential',
        severity: 'CRITICAL',
        describe: (m) => `GitHub Personal Access Token detected: "${m.trim()}"`,
    },
];
/**
 * Extensions that officeParser supports (confirmed from its error message).
 * Everything else is read as raw UTF-8.
 */
const OFFICE_EXTENSIONS = new Set([
    '.docx', '.pptx', '.xlsx',
    '.odt', '.odp', '.ods', '.odg',
    '.pdf', '.rtf', '.md', '.html',
    '.csv', '.epub', '.tex',
]);
/**
 * Extract plain text from the uploaded file.
 * - Office / PDF / rich formats → officeParser (returns a Promise<string>)
 * - Plain text / code → direct fs.readFileSync
 */
function extractText(filePath) {
    return __awaiter(this, void 0, void 0, function* () {
        const ext = path_1.default.extname(filePath).toLowerCase();
        if (OFFICE_EXTENSIONS.has(ext)) {
            try {
                // parseOffice resolves with the extracted text string when called without callback
                const text = yield (0, officeparser_1.parseOffice)(filePath);
                return text || '';
            }
            catch (parseErr) {
                console.warn('[FileScanner] officeParser failed, falling back to raw read:', parseErr.message);
                // Fall through to raw UTF-8 read (best-effort)
            }
        }
        // Raw read for text, code, scripts, and any unsupported office format fallback
        return fs_1.default.readFileSync(filePath, 'utf-8');
    });
}
/**
 * Run all static analysis regex rules against the extracted text.
 * De-duplicates findings by rule name to prevent flooding from repeated patterns.
 */
function runStaticAnalysis(filePath) {
    return __awaiter(this, void 0, void 0, function* () {
        const findings = [];
        let text = '';
        try {
            text = yield extractText(filePath);
        }
        catch (err) {
            findings.push({
                engine: 'StaticAnalysis',
                category: 'Extraction Error',
                detail: `Could not extract text from file: ${err.message}`,
                severity: 'INFO',
            });
            return findings;
        }
        const seenRules = new Set();
        for (const rule of STATIC_RULES) {
            rule.regex.lastIndex = 0; // Reset stateful global regex
            const match = rule.regex.exec(text);
            if (match && !seenRules.has(rule.name)) {
                seenRules.add(rule.name);
                findings.push({
                    engine: 'StaticAnalysis',
                    category: rule.category,
                    detail: rule.describe(match[0]),
                    severity: rule.severity,
                });
            }
        }
        return findings;
    });
}
// ── Aggregator ─────────────────────────────────────────────────────────────────
function aggregateStatus(findings) {
    const hasMalwareSig = findings.some((f) => f.engine === 'ClamAV' && f.category === 'Malware Signature');
    const hasCritical = findings.some((f) => f.severity === 'CRITICAL' && f.category !== 'Engine Status');
    const hasHigh = findings.some((f) => f.severity === 'HIGH');
    const hasMedium = findings.some((f) => f.severity === 'MEDIUM');
    if (hasMalwareSig || hasCritical)
        return 'Malicious';
    if (hasHigh || hasMedium)
        return 'Suspicious';
    if (findings.some((f) => f.severity === 'LOW'))
        return 'Suspicious';
    return 'Clean';
}
function buildSummary(findings, fileName) {
    const urlCount = findings.filter((f) => f.category === 'External URL').length;
    const ipCount = findings.filter((f) => f.category.includes('IP')).length;
    const clamFindings = findings.filter((f) => f.engine === 'ClamAV' && f.category === 'Malware Signature');
    const secretFindings = findings.filter((f) => f.category === 'Exposed Credential' || f.category === 'Hardcoded Secret' || f.category === 'Exposed Private Key');
    const codeFindings = findings.filter((f) => f.category === 'Dangerous Code Pattern' || f.category === 'Obfuscation Technique');
    const macroFindings = findings.filter((f) => f.category === 'Malicious Macro');
    const parts = [];
    if (clamFindings.length > 0)
        parts.push(`${clamFindings.length} malware signature(s) detected by ClamAV`);
    if (macroFindings.length > 0)
        parts.push(`${macroFindings.length} auto-executing macro(s) detected`);
    if (codeFindings.length > 0)
        parts.push(`${codeFindings.length} dangerous code pattern(s) found`);
    if (secretFindings.length > 0)
        parts.push(`${secretFindings.length} hardcoded credential(s) or key(s) exposed`);
    if (ipCount > 0)
        parts.push(`${ipCount} hardcoded IP address(es) found`);
    if (urlCount > 0)
        parts.push(`${urlCount} external URL(s) found`);
    if (parts.length === 0)
        return `"${fileName}" passed all security checks with no actionable findings.`;
    return `"${fileName}" contains: ${parts.join('; ')}.`;
}
// ── Main Export: Dual-Engine Scanner ──────────────────────────────────────────
function scanFile(filePath, originalName, fileSize) {
    return __awaiter(this, void 0, void 0, function* () {
        const [signatureFindings, staticFindings] = yield Promise.all([
            runSignatureScan(filePath),
            runStaticAnalysis(filePath),
        ]);
        const allFindings = [...signatureFindings, ...staticFindings];
        const status = aggregateStatus(allFindings);
        const summary = buildSummary(allFindings, originalName);
        return {
            status,
            summary,
            findings: allFindings,
            scannedAt: new Date().toISOString(),
            fileName: originalName,
            fileSize,
        };
    });
}
exports.scanFile = scanFile;
