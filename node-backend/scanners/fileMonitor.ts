import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Socket } from 'socket.io';
import { Finding } from './portScanner';

export const checkFileIntegrity = async (targetDir: string, socket: Socket): Promise<Finding[]> => {
  const findings: Finding[] = [];
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

    if (!fs.existsSync(targetDir)) {
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

    const files = fs.readdirSync(targetDir);
    let hashedCount = 0;

    for (const file of files) {
      const filePath = path.join(targetDir, file);
      const stat = fs.statSync(filePath);

      if (stat.isFile()) {
        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        
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

  } catch (error: any) {
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
};
