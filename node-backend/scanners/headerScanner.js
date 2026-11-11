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
exports.scanHeaders = void 0;
const axios_1 = __importDefault(require("axios"));
/**
 * Scans HTTP headers for missing security configurations.
 * @param host The target hostname or IP address
 * @param socket Socket.io instance to emit real-time logs
 * @returns A promise that resolves to an array of Findings for missing headers
 */
const scanHeaders = (host, socket) => __awaiter(void 0, void 0, void 0, function* () {
    const findings = [];
    const targetUrl = host.startsWith('http') ? host : `http://${host}`;
    const totalSteps = 4;
    let currentStep = 1;
    socket.emit('log-update', {
        step: currentStep,
        totalSteps,
        level: 'INFO',
        message: `[INFO] Fetching headers from ${targetUrl}...`,
        progress: Math.floor((currentStep / totalSteps) * 100),
    });
    try {
        const response = yield axios_1.default.get(targetUrl, { timeout: 3000 });
        const headers = response.headers;
        currentStep++;
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: `[INFO] Headers received. Analyzing security configurations...`,
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        const securityHeaders = [
            { key: 'strict-transport-security', name: 'Strict-Transport-Security (HSTS)', severity: 'HIGH' },
            { key: 'content-security-policy', name: 'Content-Security-Policy (CSP)', severity: 'MEDIUM' },
            { key: 'x-frame-options', name: 'X-Frame-Options', severity: 'MEDIUM' },
            { key: 'x-content-type-options', name: 'X-Content-Type-Options', severity: 'LOW' }
        ];
        for (const sh of securityHeaders) {
            currentStep++;
            if (!headers[sh.key]) {
                socket.emit('log-update', {
                    step: Math.min(currentStep, totalSteps),
                    totalSteps,
                    level: 'WARN',
                    message: `[WARN] Missing security header: ${sh.name}`,
                    progress: Math.floor((Math.min(currentStep, totalSteps) / totalSteps) * 100),
                });
                findings.push({
                    type: 'Missing Header',
                    description: `The HTTP response is missing the ${sh.name} header.`,
                    severity: sh.severity,
                });
            }
            else {
                socket.emit('log-update', {
                    step: Math.min(currentStep, totalSteps),
                    totalSteps,
                    level: 'SUCCESS',
                    message: `[SUCCESS] Header ${sh.name} is present.`,
                    progress: Math.floor((Math.min(currentStep, totalSteps) / totalSteps) * 100),
                });
            }
        }
    }
    catch (error) {
        socket.emit('log-update', {
            step: totalSteps,
            totalSteps,
            level: 'ALERT',
            message: `[ERROR] Failed to fetch headers from ${targetUrl}: ${error.message}`,
            progress: 100,
        });
        // Rethrow to be caught by the main socket handler if needed
        throw error;
    }
    return findings;
});
exports.scanHeaders = scanHeaders;
