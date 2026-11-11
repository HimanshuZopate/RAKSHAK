import axios from 'axios';
import { Socket } from 'socket.io';
import { Finding } from './portScanner';

/**
 * Scans HTTP headers for missing security configurations.
 * @param host The target hostname or IP address
 * @param socket Socket.io instance to emit real-time logs
 * @returns A promise that resolves to an array of Findings for missing headers
 */
export const scanHeaders = async (host: string, socket: Socket): Promise<Finding[]> => {
  const findings: Finding[] = [];
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
    const response = await axios.get(targetUrl, { timeout: 3000 });
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
          severity: sh.severity as any,
        });
      } else {
        socket.emit('log-update', {
          step: Math.min(currentStep, totalSteps),
          totalSteps,
          level: 'SUCCESS',
          message: `[SUCCESS] Header ${sh.name} is present.`,
          progress: Math.floor((Math.min(currentStep, totalSteps) / totalSteps) * 100),
        });
      }
    }
  } catch (error: any) {
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
};
