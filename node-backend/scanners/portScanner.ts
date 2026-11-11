import net from 'net';
import { Socket } from 'socket.io';

export interface Finding {
  type: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

/**
 * Scans a list of ports on a given host.
 * @param host The target hostname or IP address
 * @param ports Array of ports to scan
 * @param socket Socket.io instance to emit real-time logs
 * @returns A promise that resolves to an array of Findings for open ports
 */
export const scanPorts = async (
  host: string,
  ports: number[] = [21, 22, 80, 443, 3306, 27017],
  socket: Socket
): Promise<Finding[]> => {
  const findings: Finding[] = [];
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

    const isOpen = await checkPort(host, port, timeout);
    
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
    } else {
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
};

const checkPort = (host: string, port: number, timeout: number): Promise<boolean> => {
  return new Promise((resolve) => {
    const s = new net.Socket();
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
