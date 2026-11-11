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
exports.scanPorts = void 0;
const net_1 = __importDefault(require("net"));
/**
 * Scans a list of ports on a given host.
 * @param host The target hostname or IP address
 * @param ports Array of ports to scan
 * @param socket Socket.io instance to emit real-time logs
 * @returns A promise that resolves to an array of Findings for open ports
 */
const scanPorts = (host, ports = [21, 22, 80, 443, 3306, 27017], socket) => __awaiter(void 0, void 0, void 0, function* () {
    const findings = [];
    const timeout = 1500;
    let currentStep = 1;
    for (const port of ports) {
        socket.emit('log-update', {
            step: currentStep,
            totalSteps: ports.length,
            level: 'INFO',
            message: `[INFO] Testing port ${port} on ${host}...`,
            progress: Math.floor((currentStep / ports.length) * 100),
        });
        const isOpen = yield checkPort(host, port, timeout);
        if (isOpen) {
            socket.emit('log-update', {
                step: currentStep,
                totalSteps: ports.length,
                level: 'WARN',
                message: `[WARN] Port ${port} is OPEN!`,
                progress: Math.floor((currentStep / ports.length) * 100),
            });
            findings.push({
                type: 'Open Port',
                description: `Port ${port} is publicly accessible.`,
                severity: port === 80 || port === 443 ? 'LOW' : 'HIGH',
            });
        }
        else {
            socket.emit('log-update', {
                step: currentStep,
                totalSteps: ports.length,
                level: 'INFO',
                message: `[INFO] Port ${port} is Closed/Filtered.`,
                progress: Math.floor((currentStep / ports.length) * 100),
            });
        }
        currentStep++;
    }
    return findings;
});
exports.scanPorts = scanPorts;
const checkPort = (host, port, timeout) => {
    return new Promise((resolve) => {
        const s = new net_1.default.Socket();
        let isOpen = false;
        s.setTimeout(timeout);
        s.on('connect', () => {
            isOpen = true;
            s.destroy();
        });
        s.on('timeout', () => {
            s.destroy();
        });
        s.on('error', () => {
            s.destroy();
        });
        s.on('close', () => {
            resolve(isOpen);
        });
        s.connect(port, host);
    });
};
