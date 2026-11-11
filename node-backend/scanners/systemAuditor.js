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
exports.auditSystem = void 0;
const systeminformation_1 = __importDefault(require("systeminformation"));
const auditSystem = (socket) => __awaiter(void 0, void 0, void 0, function* () {
    const findings = [];
    let currentStep = 1;
    const totalSteps = 4;
    try {
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: '[INFO] Initializing System & Resource Auditor...',
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        // 1. Check CPU Load
        currentStep++;
        const load = yield systeminformation_1.default.currentLoad();
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: `[INFO] Current CPU Load: ${load.currentLoad.toFixed(2)}%`,
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        if (load.currentLoad > 85) {
            findings.push({
                type: 'Resource Exhaustion',
                description: `CPU load is critically high at ${load.currentLoad.toFixed(2)}%. This could indicate a DoS condition or cryptojacking.`,
                severity: 'HIGH',
            });
            socket.emit('log-update', {
                step: currentStep,
                totalSteps,
                level: 'WARN',
                message: '[WARN] High CPU load detected.',
                progress: Math.floor((currentStep / totalSteps) * 100),
            });
        }
        // 2. Check Memory
        currentStep++;
        const mem = yield systeminformation_1.default.mem();
        const memUsedPercent = (mem.active / mem.total) * 100;
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: `[INFO] Memory Usage: ${memUsedPercent.toFixed(2)}%`,
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        if (memUsedPercent > 90) {
            findings.push({
                type: 'Resource Exhaustion',
                description: `Memory utilization is above 90% (${memUsedPercent.toFixed(2)}%). Possible memory leak or overwhelming load.`,
                severity: 'HIGH',
            });
            socket.emit('log-update', {
                step: currentStep,
                totalSteps,
                level: 'WARN',
                message: '[WARN] High Memory usage detected.',
                progress: Math.floor((currentStep / totalSteps) * 100),
            });
        }
        // 3. Network Connections
        currentStep++;
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: '[INFO] Mapping active network sockets and connections...',
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        const networkConnections = yield systeminformation_1.default.networkConnections();
        const suspiciousPorts = ['4444', '1337', '31337', '6667']; // Common bind shell / IRC botnet ports
        let suspiciousCount = 0;
        for (const conn of networkConnections) {
            if (suspiciousPorts.includes(String(conn.localPort)) || suspiciousPorts.includes(String(conn.peerPort))) {
                suspiciousCount++;
                findings.push({
                    type: 'Suspicious Network Activity',
                    description: `Active connection established on high-risk port ${conn.localPort || conn.peerPort}. Protocol: ${conn.protocol}.`,
                    severity: 'CRITICAL',
                });
            }
        }
        if (suspiciousCount > 0) {
            socket.emit('log-update', {
                step: currentStep,
                totalSteps,
                level: 'ALERT',
                message: `[ALERT] Found ${suspiciousCount} suspicious network connection(s).`,
                progress: Math.floor((currentStep / totalSteps) * 100),
            });
        }
        else {
            socket.emit('log-update', {
                step: currentStep,
                totalSteps,
                level: 'SUCCESS',
                message: '[SUCCESS] Network connections map verified safe.',
                progress: Math.floor((currentStep / totalSteps) * 100),
            });
        }
    }
    catch (error) {
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'ALERT',
            message: `[ERROR] System Auditor encountered a failure: ${error.message}`,
            progress: 100,
        });
    }
    return findings;
});
exports.auditSystem = auditSystem;
