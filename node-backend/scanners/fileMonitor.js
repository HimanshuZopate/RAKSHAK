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
exports.checkFileIntegrity = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const crypto_1 = __importDefault(require("crypto"));
const checkFileIntegrity = (targetDir, socket) => __awaiter(void 0, void 0, void 0, function* () {
    const findings = [];
    let currentStep = 1;
    const totalSteps = 3;
    try {
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: `[INFO] Initializing File Integrity Monitor (FIM) for directory: ${targetDir}`,
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        if (!fs_1.default.existsSync(targetDir)) {
            throw new Error(`Target directory does not exist: ${targetDir}`);
        }
        currentStep++;
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'INFO',
            message: '[INFO] Computing SHA-256 baseline hashes for critical files...',
            progress: Math.floor((currentStep / totalSteps) * 100),
        });
        const files = fs_1.default.readdirSync(targetDir);
        let hashedCount = 0;
        for (const file of files) {
            const filePath = path_1.default.join(targetDir, file);
            const stat = fs_1.default.statSync(filePath);
            if (stat.isFile()) {
                const fileBuffer = fs_1.default.readFileSync(filePath);
                const hash = crypto_1.default.createHash('sha256').update(fileBuffer).digest('hex');
                // Emitting a log for each file might spam the socket if there are many files,
                // but since this is a predefined config/upload dir it should be fine.
                socket.emit('log-update', {
                    step: currentStep,
                    totalSteps,
                    level: 'INFO',
                    message: `[HASH] ${file} -> ${hash.substring(0, 16)}...`,
                    progress: Math.floor((currentStep / totalSteps) * 100),
                });
                hashedCount++;
            }
        }
        currentStep++;
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'SUCCESS',
            message: `[SUCCESS] FIM complete. Established baseline hashes for ${hashedCount} file(s).`,
            progress: 100,
        });
    }
    catch (error) {
        socket.emit('log-update', {
            step: currentStep,
            totalSteps,
            level: 'ALERT',
            message: `[ERROR] File Integrity Monitor failed: ${error.message}`,
            progress: 100,
        });
    }
    // FIM doesn't create warnings yet (baseline mode), just return empty findings for now
    return findings;
});
exports.checkFileIntegrity = checkFileIntegrity;
