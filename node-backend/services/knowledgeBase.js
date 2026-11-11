"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.findKnowledge = void 0;
const KNOWLEDGE = [
    {
        topic: 'phishing',
        title: 'Recognising phishing',
        content: 'Treat urgency, requests for secrets or payments, unexpected links, and mismatched domains as warning signs. Verify through an independent official channel instead of replying to the message.',
        keywords: ['phishing', 'scam', 'suspicious message', 'link', 'email'],
    },
    {
        topic: 'passwords',
        title: 'Protecting accounts',
        content: 'Use a long unique passphrase for every account, store it in a reputable password manager, and enable multifactor authentication. Never share passwords, OTPs, or recovery codes.',
        keywords: ['password', 'passphrase', 'account', 'mfa', 'multifactor', 'otp'],
    },
    {
        topic: 'website-security',
        title: 'HTTPS and website checks',
        content: 'HTTPS encrypts traffic in transit, while certificate validity and security headers provide additional configuration signals. A basic configuration scan is not a comprehensive security audit.',
        keywords: ['https', 'tls', 'certificate', 'header', 'website'],
    },
    {
        topic: 'incident-response',
        title: 'Responding to suspected fraud',
        content: 'Stop interacting with the suspected attacker, preserve evidence, contact your bank or payment provider immediately, and use official reporting channels. In India, financial cyber fraud can be reported via 1930 where applicable.',
        keywords: ['incident', 'fraud', 'clicked', 'hacked', 'report', '1930'],
    },
    {
        topic: 'application',
        title: 'Using Rakshak',
        content: 'Rakshak keeps technical security findings in deterministic scanners. AI RAKSHAK explains those findings and provides educational guidance; it cannot change scan scores, access private records, or perform privileged actions.',
        keywords: ['rakshak', 'application', 'feature', 'scan', 'dashboard'],
    },
];
const findKnowledge = (question, limit = 3) => {
    const normalized = question.toLowerCase();
    return KNOWLEDGE
        .map((item) => ({
        item,
        score: item.keywords.reduce((score, keyword) => score + (normalized.includes(keyword) ? 1 : 0), 0),
    }))
        .filter(({ score }) => score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, limit)
        .map(({ item }) => item);
};
exports.findKnowledge = findKnowledge;
