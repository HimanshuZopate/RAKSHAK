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
exports.seedServices = exports.defaultServices = void 0;
const mongoose_1 = require("mongoose");
const ServiceSchema = new mongoose_1.Schema({
    serviceId: {
        type: Number,
        required: true,
        unique: true,
    },
    name: {
        type: String,
        required: [true, 'Service name is required'],
        unique: true,
        trim: true,
    },
    description: {
        type: String,
        required: [true, 'Description is required'],
        trim: true,
    },
    status: {
        type: String,
        enum: ['Active', 'Pending', 'Maintenance'],
        default: 'Active',
    },
    lastRun: {
        type: Date,
        default: null,
    },
    iconKey: {
        type: String,
        default: 'ShieldAlert',
    },
    color: {
        type: String,
        default: 'from-blue-500 to-indigo-600',
    },
    shadow: {
        type: String,
        default: 'shadow-blue-500/30',
    },
    metrics: {
        type: String,
        default: 'System Secure',
    },
    severity: {
        type: String,
        enum: ['Critical', 'High', 'Medium', 'Low', 'None'],
        default: 'Low',
    },
}, {
    timestamps: true,
});
const ServiceModel = (0, mongoose_1.model)('Service', ServiceSchema);
/**
 * Default 6 core security tools metadata to seed on initialization
 */
exports.defaultServices = [
    {
        serviceId: 1,
        name: 'Vulnerability Scanner',
        description: 'Scan your system for known vulnerabilities, CVEs, and outdated libraries.',
        status: 'Active',
        iconKey: 'ShieldAlert',
        color: 'from-red-500 to-rose-600',
        shadow: 'shadow-red-500/30',
        metrics: '24 Issues Found',
        severity: 'High',
        lastRun: new Date(Date.now() - 3600000 * 2),
    },
    {
        serviceId: 2,
        name: 'Phishing & Scam Detector',
        description: 'Analyze suspicious URLs, emails, SMS messages, and online messages to identify phishing indicators, potential scams, and recommended safety actions.',
        status: 'Active',
        iconKey: 'ShieldAlert',
        color: 'from-orange-500 to-red-600',
        shadow: 'shadow-orange-500/30',
        metrics: 'Threat Analysis Ready',
        severity: 'Low',
        lastRun: new Date(Date.now() - 3600000 * 5),
    },
    {
        serviceId: 3,
        name: 'Security Audits',
        description: 'Client environment & network audit: browser telemetry, privacy leaks, and firewall port scanning.',
        status: 'Active',
        iconKey: 'ShieldCheck',
        color: 'from-cyan-500 to-blue-600',
        shadow: 'shadow-cyan-500/30',
        metrics: 'Client & Network Audit',
        severity: 'Low',
        lastRun: new Date(),
    },
    {
        serviceId: 7,
        name: 'Password Security Lab',
        description: 'Evaluate password strength, identify predictable patterns, and generate secure passwords privately in your browser.',
        status: 'Active',
        iconKey: 'KeyRound',
        color: 'from-cyan-500 to-blue-600',
        shadow: 'shadow-cyan-500/30',
        metrics: 'Client-Side Analysis',
        severity: 'Low',
        lastRun: new Date(),
    },
    {
        serviceId: 8,
        name: 'Website Security Scanner',
        description: 'Check HTTPS availability, inspect TLS certificate information, review HTTP security headers, and identify basic website configuration concerns.',
        status: 'Active',
        iconKey: 'Globe',
        color: 'from-blue-600 to-cyan-500',
        shadow: 'shadow-cyan-500/30',
        metrics: 'HTTP & TLS Verified',
        severity: 'Low',
        lastRun: new Date(),
    },
];
/**
 * Seed initial services if collection is empty
 */
const seedServices = () => __awaiter(void 0, void 0, void 0, function* () {
    try {
        // Permanently remove retired services (Intrusion Detection, API Monitoring, Data Encryption)
        yield ServiceModel.deleteMany({
            $or: [
                { serviceId: { $in: [4, 5, 6] } },
                { name: { $in: ['Intrusion Detection', 'API Monitoring', 'Data Encryption'] } },
            ],
        });
        const count = yield ServiceModel.countDocuments();
        if (count === 0) {
            console.log('🌱 Seeding default security services into database...');
            yield ServiceModel.insertMany(exports.defaultServices);
            console.log('✅ Security services seeded successfully.');
        }
        else {
            // Auto-migrate: ensure service #2 is updated to Phishing & Scam Detector even if DB was already seeded
            const phishingDef = exports.defaultServices.find((s) => s.serviceId === 2);
            if (phishingDef) {
                yield ServiceModel.updateOne({ serviceId: 2 }, {
                    $set: {
                        name: phishingDef.name,
                        description: phishingDef.description,
                        status: phishingDef.status,
                        iconKey: phishingDef.iconKey,
                        color: phishingDef.color,
                        shadow: phishingDef.shadow,
                        metrics: phishingDef.metrics,
                        severity: phishingDef.severity,
                    },
                });
            }
            // Auto-migrate: ensure Service #7 (Password Security Lab) is upserted
            const passDef = exports.defaultServices.find((s) => s.serviceId === 7);
            if (passDef) {
                yield ServiceModel.updateOne({ serviceId: 7 }, {
                    $setOnInsert: {
                        serviceId: passDef.serviceId,
                        name: passDef.name,
                        description: passDef.description,
                        status: passDef.status,
                        iconKey: passDef.iconKey,
                        color: passDef.color,
                        shadow: passDef.shadow,
                        metrics: passDef.metrics,
                        severity: passDef.severity,
                        lastRun: passDef.lastRun,
                    },
                }, { upsert: true });
            }
            // Auto-migrate: ensure Service #8 (Website Security Scanner) is upserted
            const webDef = exports.defaultServices.find((s) => s.serviceId === 8);
            if (webDef) {
                yield ServiceModel.updateOne({ serviceId: 8 }, {
                    $setOnInsert: {
                        serviceId: webDef.serviceId,
                        name: webDef.name,
                        description: webDef.description,
                        status: webDef.status,
                        iconKey: webDef.iconKey,
                        color: webDef.color,
                        shadow: webDef.shadow,
                        metrics: webDef.metrics,
                        severity: webDef.severity,
                        lastRun: webDef.lastRun,
                    },
                }, { upsert: true });
            }
        }
    }
    catch (err) {
        console.error('Error seeding security services:', err);
    }
});
exports.seedServices = seedServices;
exports.default = ServiceModel;
