import si from 'systeminformation';
import { Socket } from 'socket.io';
import { Finding } from './portScanner'; // Re-use the Finding interface

export const auditSystem = async (socket: Socket): Promise<Finding[]> => {
  const findings: Finding[] = [];
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
    const load = await si.currentLoad();
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
    const mem = await si.mem();
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

    const networkConnections = await si.networkConnections();
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
    } else {
      socket.emit('log-update', {
        step: currentStep,
        totalSteps,
        level: 'SUCCESS',
        message: '[SUCCESS] Network connections map verified safe.',
        progress: Math.floor((currentStep / totalSteps) * 100),
      });
    }

  } catch (error: any) {
    socket.emit('log-update', {
      step: currentStep,
      totalSteps,
      level: 'ALERT',
      message: `[ERROR] System Auditor encountered a failure: ${error.message}`,
      progress: 100,
    });
  }

  return findings;
};
