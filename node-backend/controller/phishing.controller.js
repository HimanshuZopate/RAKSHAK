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
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeMessageHandler = exports.analyzeUrlHandler = void 0;
const auditService_1 = require("../services/auditService");
// ──────────────────────────────────────────────────────────────────────────────
// Phishing & Scam Detection Controller
// Implements URL analysis, phishing message detection, and email/SMS scam
// analysis using heuristic pattern matching and optional external APIs.
// ──────────────────────────────────────────────────────────────────────────────
/** Risk level thresholds – documented for transparency */
const RISK_THRESHOLDS = {
    LOW_MAX: 29,
    MEDIUM_MAX: 59,
    // 60–100 = High
};
// ─── Known Suspicious Patterns ───────────────────────────────────────────────
const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.cf', '.tk', '.ga',
    '.buzz', '.surf', '.rest', '.icu', '.cam', '.bid', '.win', '.stream',
];
const LEGITIMATE_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'short.io', 'cutt.ly',
];
const IMPERSONATION_DOMAINS = [
    'paypa1', 'paypal-secure', 'paypall', 'g00gle', 'googlle', 'go0gle',
    'micros0ft', 'mlcrosoft', 'amaz0n', 'amazzon', 'amazonn', 'app1e',
    'faceb00k', 'lnstagram', 'netfl1x', 'netfllx', 'whatsaapp',
    'bankofamerica-secure', 'chase-verify', 'wellsfarg0',
];
const PHISHING_KEYWORDS = [
    { pattern: /\b(verify your account)\b/i, weight: 12, desc: 'Account verification request' },
    { pattern: /\b(suspended|deactivated|locked)\b.*\b(account|access)\b/i, weight: 15, desc: 'Account threat/suspension claim' },
    { pattern: /\b(click here|click below)\b.*\b(immediately|now|within)\b/i, weight: 10, desc: 'Urgency-driven click request' },
    { pattern: /\b(confirm your (identity|password|information))\b/i, weight: 14, desc: 'Credential harvesting request' },
    { pattern: /\b(send|transfer|wire)\b.*\b(\$|USD|₹|INR|£|€|bitcoin|crypto)\b/i, weight: 18, desc: 'Financial transfer request' },
    { pattern: /\b(won|winner|congratulations|lottery|prize)\b.*\b(claim|collect)\b/i, weight: 16, desc: 'Prize/lottery scam pattern' },
    { pattern: /\b(OTP|one.?time.?password|verification code)\b.*\b(share|send|provide|enter)\b/i, weight: 20, desc: 'OTP/code theft attempt' },
    { pattern: /\b(social security|SSN|passport number|aadhaar)\b/i, weight: 18, desc: 'Government ID solicitation' },
    { pattern: /\b(tax refund|IRS|income tax)\b.*\b(claim|verify|pending)\b/i, weight: 15, desc: 'Tax scam impersonation' },
    { pattern: /\b(dear customer|dear user|dear sir\/madam)\b/i, weight: 5, desc: 'Generic impersonal greeting' },
    { pattern: /\b(act now|limited time|expire|expires in)\b/i, weight: 8, desc: 'Artificial urgency' },
    { pattern: /\b(update your payment|billing information|card details)\b/i, weight: 14, desc: 'Payment information phishing' },
    { pattern: /\b(unusual activity|suspicious login|unauthorized)\b/i, weight: 10, desc: 'Fear-based alert pattern' },
    { pattern: /\b(whatsapp|telegram)\b.*\b(forward|share)\b.*\b(contacts|friends)\b/i, weight: 12, desc: 'Chain message pattern' },
    { pattern: /\b(nigerian prince|inheritance|unclaimed funds)\b/i, weight: 22, desc: 'Advance fee fraud pattern' },
];
// URL-embedded patterns
const URL_IN_TEXT_PATTERN = /https?:\/\/[^\s<>"']+/gi;
const IP_URL_PATTERN = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
const ENCODED_URL_PATTERN = /%[0-9A-Fa-f]{2}/;
const AT_SYMBOL_PATTERN = /https?:\/\/[^/]*@/;
const EXCESSIVE_SUBDOMAINS = /^https?:\/\/([^/]+\.){4,}/;
// ─── Helper Functions ────────────────────────────────────────────────────────
/**
 * Sanitize input for safe preview display (no HTML injection)
 */
function sanitizePreview(input, maxLen = 120) {
    const cleaned = input
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    return cleaned.length > maxLen ? cleaned.substring(0, maxLen) + '...' : cleaned;
}
/**
 * Calculate risk level from numeric score
 */
function scoreToLevel(score) {
    if (score <= RISK_THRESHOLDS.LOW_MAX)
        return 'Low';
    if (score <= RISK_THRESHOLDS.MEDIUM_MAX)
        return 'Medium';
    return 'High';
}
/**
 * Clamp a number between min and max
 */
function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}
/**
 * Validate URL format (only http/https)
 */
function isValidHttpUrl(urlString) {
    try {
        const url = new URL(urlString);
        return url.protocol === 'http:' || url.protocol === 'https:';
    }
    catch (_a) {
        return false;
    }
}
// ─── URL Analysis Engine ─────────────────────────────────────────────────────
function analyzeUrl(rawUrl) {
    const warnings = [];
    const limitations = [];
    let url;
    // Normalize URL
    let normalizedUrl = rawUrl.trim();
    if (!normalizedUrl.match(/^https?:\/\//i)) {
        normalizedUrl = 'https://' + normalizedUrl;
    }
    try {
        url = new URL(normalizedUrl);
    }
    catch (_a) {
        return {
            riskLevel: 'Unknown',
            riskScore: 0,
            summary: 'The provided input could not be parsed as a valid URL.',
            warningSignsDetected: [],
            recommendedActions: ['Verify that the URL is correctly formatted before visiting it.'],
            analysisTimestamp: new Date().toISOString(),
            analysisType: 'url',
            inputPreview: sanitizePreview(rawUrl),
            disclaimer: 'This analysis is based on pattern matching and does not guarantee the URL is safe or malicious.',
            limitations: ['Input could not be parsed as a URL.'],
        };
    }
    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    // Check 1: IP-based URL
    if (IP_URL_PATTERN.test(normalizedUrl)) {
        warnings.push({
            indicator: 'IP Address URL',
            description: 'The URL uses a raw IP address instead of a domain name. Legitimate services rarely use IP-based URLs.',
            severity: 'high',
            weight: 20,
        });
    }
    // Check 2: Suspicious TLD
    const matchedTld = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
    if (matchedTld) {
        warnings.push({
            indicator: `Suspicious TLD (${matchedTld})`,
            description: `The domain uses "${matchedTld}" which is frequently associated with throwaway phishing domains.`,
            severity: 'medium',
            weight: 12,
        });
    }
    // Check 3: URL shortener
    const isShortener = LEGITIMATE_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
    if (isShortener) {
        warnings.push({
            indicator: 'URL Shortener Detected',
            description: 'Shortened URLs can hide the actual destination. The real target cannot be determined without following the redirect.',
            severity: 'medium',
            weight: 10,
        });
        limitations.push('URL shortener detected – the actual destination cannot be analyzed without following the redirect, which this tool does not do for safety reasons.');
    }
    // Check 4: Impersonation domain
    const impersonation = IMPERSONATION_DOMAINS.find(d => hostname.includes(d));
    if (impersonation) {
        warnings.push({
            indicator: 'Possible Domain Impersonation',
            description: `The domain contains "${impersonation}" which may be an attempt to impersonate a well-known brand using a deceptive spelling.`,
            severity: 'high',
            weight: 25,
        });
    }
    // Check 5: Excessive subdomains
    if (EXCESSIVE_SUBDOMAINS.test(normalizedUrl)) {
        warnings.push({
            indicator: 'Excessive Subdomains',
            description: 'The URL contains an unusually large number of subdomains, which is a technique used to hide the actual domain.',
            severity: 'medium',
            weight: 10,
        });
    }
    // Check 6: @ symbol in URL (credential-based redirect trick)
    if (AT_SYMBOL_PATTERN.test(normalizedUrl)) {
        warnings.push({
            indicator: 'Credential Redirect Trick',
            description: 'The URL contains an "@" symbol which can be used to mask the actual destination by placing a fake hostname before it.',
            severity: 'high',
            weight: 22,
        });
    }
    // Check 7: Encoded characters (obfuscation)
    if (ENCODED_URL_PATTERN.test(pathname)) {
        warnings.push({
            indicator: 'URL Encoding Obfuscation',
            description: 'The URL path contains percent-encoded characters that may be used to hide the actual content path.',
            severity: 'low',
            weight: 6,
        });
    }
    // Check 8: Very long URL (potential obfuscation)
    if (normalizedUrl.length > 200) {
        warnings.push({
            indicator: 'Unusually Long URL',
            description: 'The URL is abnormally long, which is sometimes used to hide suspicious parameters or obfuscate the destination.',
            severity: 'low',
            weight: 5,
        });
    }
    // Check 9: Non-HTTPS
    if (url.protocol === 'http:') {
        warnings.push({
            indicator: 'No HTTPS Encryption',
            description: 'The URL uses HTTP instead of HTTPS. Data sent to this site would not be encrypted.',
            severity: 'medium',
            weight: 8,
        });
    }
    // Check 10: Suspicious path patterns (login, verify, update, secure)
    const suspiciousPathPatterns = [
        { pattern: /\/(login|signin|log-in)/i, desc: 'Login page path' },
        { pattern: /\/(verify|confirm|validate)/i, desc: 'Verification page path' },
        { pattern: /\/(secure|security|account)/i, desc: 'Security-themed path' },
        { pattern: /\/(update|reset|recover)/i, desc: 'Credential update path' },
        { pattern: /\/(payment|billing|invoice)/i, desc: 'Payment-related path' },
    ];
    const pathWarnings = suspiciousPathPatterns.filter(p => p.pattern.test(pathname));
    if (pathWarnings.length >= 2) {
        warnings.push({
            indicator: 'Multiple Suspicious Path Keywords',
            description: `The URL path contains multiple sensitive keywords: ${pathWarnings.map(p => p.desc).join(', ')}. This combination is commonly seen in phishing pages.`,
            severity: 'medium',
            weight: 10,
        });
    }
    // Check 11: Lookalike characters (homograph attack hints)
    const homographHints = /[а-яА-Я]|xn--/; // Cyrillic chars or punycode
    if (homographHints.test(hostname)) {
        warnings.push({
            indicator: 'Possible Homograph Attack',
            description: 'The domain contains characters from non-Latin scripts or internationalized domain encoding, which can be used to mimic legitimate domains.',
            severity: 'high',
            weight: 22,
        });
    }
    // Calculate risk score
    const rawScore = warnings.reduce((sum, w) => sum + w.weight, 0);
    const riskScore = clamp(rawScore, 0, 100);
    const riskLevel = warnings.length === 0 ? 'Low' : scoreToLevel(riskScore);
    // Generate recommendations
    const recommendedActions = [];
    if (riskLevel === 'High') {
        recommendedActions.push('Do NOT visit this URL. It displays multiple characteristics of a phishing or malicious website.');
        recommendedActions.push('If you received this link in an email or message, report it as spam or phishing.');
        recommendedActions.push('Do not enter any personal information, credentials, or payment details on this site.');
    }
    else if (riskLevel === 'Medium') {
        recommendedActions.push('Proceed with caution. Verify the legitimacy of this URL before entering any personal information.');
        recommendedActions.push('Check that the domain exactly matches the official website of the organization.');
        recommendedActions.push('Look for additional verification such as SSL certificate details in your browser.');
    }
    else {
        recommendedActions.push('No significant suspicious indicators were detected, but always verify URLs before entering sensitive information.');
        recommendedActions.push('Check the browser\'s address bar for HTTPS and a valid certificate before submitting credentials.');
    }
    limitations.push('This analysis is based on pattern matching and known indicators. It does not verify the actual content served by the URL.');
    limitations.push('A low risk score does not guarantee the URL is safe; it means no known suspicious patterns were detected.');
    const summary = warnings.length === 0
        ? 'No suspicious indicators were detected in this URL. However, this does not confirm the URL is safe.'
        : `${warnings.length} suspicious indicator(s) detected. ${riskLevel} risk level based on pattern analysis.`;
    return {
        riskLevel,
        riskScore,
        summary,
        warningSignsDetected: warnings,
        recommendedActions,
        analysisTimestamp: new Date().toISOString(),
        analysisType: 'url',
        inputPreview: sanitizePreview(normalizedUrl, 200),
        disclaimer: 'This analysis is based on heuristic pattern detection. No automated tool can guarantee a URL is safe or malicious. Exercise personal judgment.',
        limitations,
    };
}
// ─── Message Analysis Engine ─────────────────────────────────────────────────
function analyzeMessage(text, analysisType, senderInfo) {
    const warnings = [];
    const limitations = [];
    // Check for embedded URLs
    const embeddedUrls = text.match(URL_IN_TEXT_PATTERN) || [];
    if (embeddedUrls.length > 0) {
        // Analyze each embedded URL
        for (const embeddedUrl of embeddedUrls.slice(0, 5)) { // limit to 5
            const urlResult = analyzeUrl(embeddedUrl);
            if (urlResult.riskScore > RISK_THRESHOLDS.LOW_MAX) {
                warnings.push({
                    indicator: `Suspicious Embedded URL`,
                    description: `The message contains a suspicious URL: ${sanitizePreview(embeddedUrl, 80)}. ${urlResult.summary}`,
                    severity: urlResult.riskLevel === 'High' ? 'high' : 'medium',
                    weight: Math.min(urlResult.riskScore / 2, 20), // contribute proportionally
                });
            }
        }
        if (embeddedUrls.length > 3) {
            warnings.push({
                indicator: 'Multiple URLs in Message',
                description: `The message contains ${embeddedUrls.length} URLs, which is unusual for legitimate communications.`,
                severity: 'medium',
                weight: 8,
            });
        }
    }
    // Check phishing keyword patterns
    let matchedPatterns = 0;
    for (const kw of PHISHING_KEYWORDS) {
        if (kw.pattern.test(text)) {
            matchedPatterns++;
            warnings.push({
                indicator: kw.desc,
                description: `The message contains language matching a known ${kw.desc.toLowerCase()} pattern.`,
                severity: kw.weight >= 15 ? 'high' : kw.weight >= 10 ? 'medium' : 'low',
                weight: kw.weight,
            });
        }
    }
    // Check for excessive urgency indicators (but don't flag single occurrence of common words)
    const urgencyWords = text.match(/\b(urgent|immediately|right now|act fast|hurry|limited time|expires? today)\b/gi);
    if (urgencyWords && urgencyWords.length >= 2) {
        warnings.push({
            indicator: 'Multiple Urgency Indicators',
            description: `The message uses ${urgencyWords.length} urgency-creating phrases ("${urgencyWords.slice(0, 3).join('", "')}"), a common tactic to pressure victims into acting without thinking.`,
            severity: 'medium',
            weight: 10,
        });
    }
    // Check for request for personal information
    const personalInfoPatterns = [
        /\b(credit card|debit card|card number|CVV|expiry date)\b/i,
        /\b(bank account|routing number|IFSC|SWIFT)\b/i,
        /\b(password|passwd|pin code|security question)\b/i,
        /\b(date of birth|DOB|mother'?s? maiden name)\b/i,
    ];
    const personalInfoMatches = personalInfoPatterns.filter(p => p.test(text));
    if (personalInfoMatches.length > 0) {
        warnings.push({
            indicator: 'Personal/Financial Information Request',
            description: 'The message asks for sensitive personal or financial information. Legitimate organizations do not request such information via email or text.',
            severity: 'high',
            weight: 18,
        });
    }
    // Check for sender impersonation patterns (email/SMS mode)
    if (analysisType === 'email_sms' && senderInfo) {
        const sender = senderInfo.toLowerCase().trim();
        // Check if sender email domain looks spoofed
        const emailMatch = sender.match(/@([^@\s]+)$/);
        if (emailMatch) {
            const senderDomain = emailMatch[1];
            const impersonation = IMPERSONATION_DOMAINS.find(d => senderDomain.includes(d));
            if (impersonation) {
                warnings.push({
                    indicator: 'Suspicious Sender Domain',
                    description: `The sender's domain contains "${impersonation}" which may be impersonating a well-known brand.`,
                    severity: 'high',
                    weight: 20,
                });
            }
            // Check for free email providers posing as organizations
            const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com'];
            if (freeProviders.includes(senderDomain)) {
                const claimsOrg = /\b(official|team|support|admin|department|hr|helpdesk)\b/i.test(text);
                if (claimsOrg) {
                    warnings.push({
                        indicator: 'Free Email Claiming Organization Identity',
                        description: 'The message appears to claim affiliation with an organization, but the sender uses a free email provider. Legitimate organizations typically use their own domain.',
                        severity: 'medium',
                        weight: 12,
                    });
                }
            }
        }
        // Check phone number patterns for SMS
        if (!emailMatch && sender.match(/^\+?\d{7,15}$/)) {
            // It's a phone number – limited analysis available
            limitations.push('Sender phone number verification is not available. The sender identity could not be confirmed.');
        }
    }
    // Check for grammar/spelling red flags common in scams
    const poorGrammarIndicators = [
        /\b(kindly|do the needful|revert back|Dear Sir\/Madam)\b/i,
        /\$\s*\d+.*\b(million|billion)\b/i,
    ];
    const grammarHits = poorGrammarIndicators.filter(p => p.test(text));
    if (grammarHits.length > 0 && matchedPatterns >= 1) {
        warnings.push({
            indicator: 'Common Scam Language Patterns',
            description: 'The message contains phrasing commonly found in scam communications, combined with other suspicious indicators.',
            severity: 'low',
            weight: 6,
        });
    }
    // Calculate risk score
    const rawScore = warnings.reduce((sum, w) => sum + w.weight, 0);
    const riskScore = clamp(rawScore, 0, 100);
    const riskLevel = warnings.length === 0 ? 'Low' : scoreToLevel(riskScore);
    // Generate recommendations
    const recommendedActions = [];
    if (riskLevel === 'High') {
        recommendedActions.push('This message displays multiple characteristics of a phishing or scam attempt.');
        recommendedActions.push('Do not click any links, download attachments, or reply with personal information.');
        recommendedActions.push('Report this message as spam/phishing in your email client or messaging app.');
        recommendedActions.push('If you believe your account may be compromised, contact the organization directly using their official website or phone number.');
    }
    else if (riskLevel === 'Medium') {
        recommendedActions.push('This message contains some suspicious indicators. Verify the sender\'s identity independently before taking any action.');
        recommendedActions.push('Do not click links in the message. Instead, navigate to the organization\'s website directly.');
        recommendedActions.push('Never share OTPs, passwords, or financial details in response to unsolicited messages.');
    }
    else {
        recommendedActions.push('No significant suspicious indicators were detected, but always exercise caution with unexpected messages.');
        recommendedActions.push('Verify the sender through independent channels if the message requests any action.');
    }
    limitations.push('This analysis uses pattern matching against known phishing indicators. It cannot verify the actual intent of the sender.');
    limitations.push('A low risk score means no known suspicious patterns were detected, not that the message is confirmed safe.');
    const summary = warnings.length === 0
        ? 'No suspicious phishing or scam indicators were detected in this message. This does not confirm the message is legitimate.'
        : `${warnings.length} suspicious indicator(s) identified. ${riskLevel} risk level based on content analysis.`;
    return {
        riskLevel,
        riskScore,
        summary,
        warningSignsDetected: warnings,
        recommendedActions,
        analysisTimestamp: new Date().toISOString(),
        analysisType,
        inputPreview: sanitizePreview(text),
        disclaimer: 'This analysis is based on heuristic pattern detection. It represents observed risk indicators, not a verified probability that the content is malicious.',
        limitations,
    };
}
// ─── Express Route Handlers ──────────────────────────────────────────────────
/**
 * POST /api/phishing/analyze-url
 * Analyzes a suspicious URL for phishing indicators
 */
const analyzeUrlHandler = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { url } = req.body;
        const requestId = (0, auditService_1.getRequestId)(req);
        const actor = (0, auditService_1.getActorContext)(req);
        if (!url || typeof url !== 'string') {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'phishing_url_analysis_rejected',
                category: 'phishing',
                status: 'denied',
                severity: 'low',
                source: 'phishing',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { reason: 'missing_url' },
                errorCode: 'INVALID_INPUT',
            });
            return res.status(400).json({
                error: 'A valid URL string is required in the request body.',
                code: 'INVALID_INPUT',
            });
        }
        if (url.length > 2048) {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'phishing_url_analysis_rejected',
                category: 'phishing',
                status: 'denied',
                severity: 'low',
                source: 'phishing',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { url: (0, auditService_1.safeUrlPreview)(url), reason: 'input_too_long' },
                errorCode: 'INPUT_TOO_LONG',
            });
            return res.status(400).json({
                error: 'URL exceeds maximum allowed length of 2048 characters.',
                code: 'INPUT_TOO_LONG',
            });
        }
        // Reject non-HTTP protocols early
        const trimmed = url.trim();
        if (trimmed.match(/^(javascript|data|vbscript|file|ftp):/i)) {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'phishing_url_analysis_rejected',
                category: 'phishing',
                status: 'denied',
                severity: 'medium',
                source: 'phishing',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { url: (0, auditService_1.safeUrlPreview)(trimmed), reason: 'unsupported_protocol' },
                errorCode: 'UNSUPPORTED_PROTOCOL',
            });
            return res.status(400).json({
                error: 'Only HTTP and HTTPS URLs are supported for analysis.',
                code: 'UNSUPPORTED_PROTOCOL',
            });
        }
        yield (0, auditService_1.recordAuditEvent)({
            action: 'phishing_url_analysis_requested',
            category: 'phishing',
            status: 'success',
            severity: 'low',
            source: 'phishing',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            resourceType: 'url',
            resourceId: (0, auditService_1.safeUrlPreview)(trimmed),
            metadata: { url: (0, auditService_1.safeUrlPreview)(trimmed), analysisType: 'url' },
        });
        const result = analyzeUrl(trimmed);
        yield (0, auditService_1.recordAuditEvent)({
            action: 'phishing_url_analysis_completed',
            category: 'phishing',
            status: 'success',
            severity: result.riskLevel === 'High' ? 'high' : result.riskLevel === 'Medium' ? 'medium' : 'low',
            source: 'phishing',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            resourceType: 'url',
            resourceId: (0, auditService_1.safeUrlPreview)(trimmed),
            metadata: {
                url: (0, auditService_1.safeUrlPreview)(trimmed),
                riskLevel: result.riskLevel,
                riskScore: result.riskScore,
            },
        });
        return res.status(200).json({
            success: true,
            result,
        });
    }
    catch (error) {
        const requestId = (0, auditService_1.getRequestId)(req);
        const actor = (0, auditService_1.getActorContext)(req);
        yield (0, auditService_1.recordAuditEvent)({
            action: 'phishing_url_analysis_failed',
            category: 'phishing',
            status: 'failure',
            severity: 'high',
            source: 'phishing',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            errorCode: 'ANALYSIS_ERROR',
        });
        console.error('Error in URL analysis:', error);
        return res.status(500).json({
            error: 'An internal error occurred during URL analysis.',
            code: 'ANALYSIS_ERROR',
        });
    }
});
exports.analyzeUrlHandler = analyzeUrlHandler;
/**
 * POST /api/phishing/analyze-message
 * Analyzes suspicious message content (email, SMS, WhatsApp, etc.)
 */
const analyzeMessageHandler = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { message, senderInfo, analysisType } = req.body;
        const requestId = (0, auditService_1.getRequestId)(req);
        const actor = (0, auditService_1.getActorContext)(req);
        if (!message || typeof message !== 'string') {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'phishing_message_analysis_rejected',
                category: 'phishing',
                status: 'denied',
                severity: 'low',
                source: 'phishing',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { reason: 'missing_message' },
                errorCode: 'INVALID_INPUT',
            });
            return res.status(400).json({
                error: 'A message text string is required in the request body.',
                code: 'INVALID_INPUT',
            });
        }
        if (message.length > 10000) {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'phishing_message_analysis_rejected',
                category: 'phishing',
                status: 'denied',
                severity: 'low',
                source: 'phishing',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { reason: 'input_too_long' },
                errorCode: 'INPUT_TOO_LONG',
            });
            return res.status(400).json({
                error: 'Message exceeds maximum allowed length of 10,000 characters.',
                code: 'INPUT_TOO_LONG',
            });
        }
        if (senderInfo && typeof senderInfo === 'string' && senderInfo.length > 320) {
            yield (0, auditService_1.recordAuditEvent)({
                action: 'phishing_message_analysis_rejected',
                category: 'phishing',
                status: 'denied',
                severity: 'low',
                source: 'phishing',
                requestId,
                actorId: actor.actorId,
                actorType: actor.actorType,
                metadata: { reason: 'sender_info_too_long' },
                errorCode: 'INPUT_TOO_LONG',
            });
            return res.status(400).json({
                error: 'Sender info exceeds maximum allowed length.',
                code: 'INPUT_TOO_LONG',
            });
        }
        const type = analysisType === 'email_sms' ? 'email_sms' : 'message';
        yield (0, auditService_1.recordAuditEvent)({
            action: 'phishing_message_analysis_requested',
            category: 'phishing',
            status: 'success',
            severity: 'low',
            source: 'phishing',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            resourceType: 'message',
            metadata: { analysisType: type, senderInfo: senderInfo ? senderInfo.slice(0, 120) : undefined },
        });
        const result = analyzeMessage(message.trim(), type, senderInfo === null || senderInfo === void 0 ? void 0 : senderInfo.trim());
        yield (0, auditService_1.recordAuditEvent)({
            action: 'phishing_message_analysis_completed',
            category: 'phishing',
            status: 'success',
            severity: result.riskLevel === 'High' ? 'high' : result.riskLevel === 'Medium' ? 'medium' : 'low',
            source: 'phishing',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            resourceType: 'message',
            metadata: {
                analysisType: type,
                riskLevel: result.riskLevel,
                riskScore: result.riskScore,
            },
        });
        return res.status(200).json({
            success: true,
            result,
        });
    }
    catch (error) {
        const requestId = (0, auditService_1.getRequestId)(req);
        const actor = (0, auditService_1.getActorContext)(req);
        yield (0, auditService_1.recordAuditEvent)({
            action: 'phishing_message_analysis_failed',
            category: 'phishing',
            status: 'failure',
            severity: 'high',
            source: 'phishing',
            requestId,
            actorId: actor.actorId,
            actorType: actor.actorType,
            errorCode: 'ANALYSIS_ERROR',
        });
        console.error('Error in message analysis:', error);
        return res.status(500).json({
            error: 'An internal error occurred during message analysis.',
            code: 'ANALYSIS_ERROR',
        });
    }
});
exports.analyzeMessageHandler = analyzeMessageHandler;
