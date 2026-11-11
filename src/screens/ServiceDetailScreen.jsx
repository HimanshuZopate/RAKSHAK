import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { io } from 'socket.io-client';
import api from '../utils/api';
import CreateTargetModal from '../components/CreateTargetModal';
import { generateScanPDF } from '../utils/pdfGenerator';
import FileScannerScreen from './FileScannerScreen';
import ClientAuditScreen from './ClientAuditScreen';
import PhishingDetectorScreen from './PhishingDetectorScreen';
import PasswordSecurityScreen from './PasswordSecurityScreen';
import WebsiteSecurityScreen from './WebsiteSecurityScreen';
import {
  ShieldAlert,
  Users,
  FileText,
  Activity,
  Server,
  Lock,
  ArrowLeft,
  Play,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Terminal,
  Copy,
  Check,
  Download,
  Clock,
  Radio,
  FileCode,
} from 'lucide-react';

const iconMap = {
  ShieldAlert,
  Users,
  FileText,
  Activity,
  Server,
  Lock,
};

const SOCKET_SERVER_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:3001';

const ServiceDetailScreen = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  // Service State
  const [service, setService] = useState(null);
  const [isLoadingService, setIsLoadingService] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');

  // Socket & Live Execution State
  const [socketConnected, setSocketConnected] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState({ step: 0, total: 0 });
  const [logs, setLogs] = useState([]);
  const [scanReport, setScanReport] = useState(null);
  const [copiedLogs, setCopiedLogs] = useState(false);

  // Targets State
  const [targets, setTargets] = useState([]);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [isTargetModalOpen, setIsTargetModalOpen] = useState(false);

  const socketRef = useRef(null);
  const terminalBottomRef = useRef(null);

  // Auto-scroll terminal on new log lines
  useEffect(() => {
    if (terminalBottomRef.current) {
      terminalBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Fetch service metadata from REST API
  useEffect(() => {
    if (id === '3') {
      setService({ serviceId: 3, name: 'Security Audits' });
      setIsLoadingService(false);
      return;
    }

    if (id === '2') {
      setService({ serviceId: 2, name: 'Phishing & Scam Detector' });
      setIsLoadingService(false);
      return;
    }

    if (id === '7') {
      setService({ serviceId: 7, name: 'Password Security Lab' });
      setIsLoadingService(false);
      return;
    }

    if (id === '8') {
      setService({ serviceId: 8, name: 'Website Security Scanner' });
      setIsLoadingService(false);
      return;
    }

    const fetchServiceDetails = async () => {
      try {
        setIsLoadingService(true);
        const res = await api.get(`/services/${id}`);
        if (res.data?.service) {
          setService(res.data.service);
        } else {
          setErrorMessage('Service details could not be found.');
        }
      } catch (err) {
        console.error('Error loading service:', err);
        setErrorMessage('Failed to connect to service registry.');
      } finally {
        setIsLoadingService(false);
      }
    };

    fetchServiceDetails();
  }, [id]);

  const fetchTargets = async () => {
    try {
      const res = await api.get('/targets');
      if (res.data?.success) {
        setTargets(res.data.targets);
        if (res.data.targets.length > 0) {
          setSelectedTargetId(res.data.targets[0]._id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch targets:', err);
    }
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  // Initialize and manage authenticated Socket.io connection
  useEffect(() => {
    if (id === '3' || id === '1' || id === '2' || id === '7') return;

    // Connect to backend with credentials so HttpOnly accessToken cookie is transmitted
    const socket = io(SOCKET_SERVER_URL, {
      withCredentials: true,
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 5,
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('✅ Socket connected successfully:', socket.id);
      setSocketConnected(true);
    });

    socket.on('disconnect', () => {
      console.log('⚠️ Socket disconnected');
      setSocketConnected(false);
    });

    socket.on('connect_error', (err) => {
      console.warn('Socket connection error (Authentication required):', err.message);
      setSocketConnected(false);
    });

    // Real-Time Log Stream Listener
    socket.on('log-update', (data) => {
      setIsRunning(true);
      setProgress(data.progress || 0);
      setCurrentStep({ step: data.step, total: data.totalSteps });
      setLogs((prev) => [
        ...prev,
        {
          timestamp: data.timestamp || new Date().toLocaleTimeString(),
          level: data.level || 'INFO',
          message: data.message || data.log?.message || data.log,
        },
      ]);
    });

    // Scan Completion Listener
    socket.on('scan-complete', (data) => {
      setIsRunning(false);
      setProgress(100);
      setScanReport(data.report);

      // Update local service lastRun
      setService((prev) => (prev ? { ...prev, lastRun: data.completedAt, status: 'Active' } : prev));

      // Append terminal completion notice
      setLogs((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          level: 'SUCCESS',
          message: `[SUCCESS] ${data.serviceName} execution finished. Security audit report generated.`,
        },
      ]);
    });

    socket.on('execution-error', (err) => {
      setIsRunning(false);
      setLogs((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          level: 'ALERT',
          message: `[ERROR] ${err.error || 'Execution encountered an error.'}`,
        },
      ]);
    });

    // Clean up socket listeners and close connection on component unmount
    return () => {
      if (socketRef.current) {
        socketRef.current.off('connect');
        socketRef.current.off('disconnect');
        socketRef.current.off('log-update');
        socketRef.current.off('scan-complete');
        socketRef.current.off('execution-error');
        socketRef.current.disconnect();
      }
    };
  }, []);

  const handleRunService = () => {
    if (!socketRef.current || isRunning || !selectedTargetId) return;

    const target = targets.find((t) => t._id === selectedTargetId);
    if (!target) return;

    // Reset previous run states
    setScanReport(null);
    setProgress(0);
    setCurrentStep({ step: 0, total: 0 });
    setIsRunning(true);
    setLogs([
      {
        timestamp: new Date().toLocaleTimeString(),
        level: 'INFO',
        message: `[REQUEST] Handshake established. Dispatching start-service-execution for ${service?.name || id}...`,
      },
      {
        timestamp: new Date().toLocaleTimeString(),
        level: 'INFO',
        message: `> Initializing scan against ${target.host} (${target.environment})...`,
      }
    ]);

    // Emit start-service-execution event to backend
    socketRef.current.emit('start-service-execution', {
      serviceId: service?.serviceId || id,
      targetId: selectedTargetId
    });
  };

  const handleCopyLogs = () => {
    const logText = logs.map((l) => `[${l.timestamp}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(logText);
    setCopiedLogs(true);
    setTimeout(() => setCopiedLogs(false), 2000);
  };

  const handleDownloadReport = () => {
    if (!scanReport) return;
    const target = targets.find(t => t._id === selectedTargetId) || { host: 'Unknown' };
    generateScanPDF(scanReport, target);
  };

  if (isLoadingService) {
    return (
      <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center text-white">
        <div className="w-16 h-16 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
        <p className="mt-4 text-slate-400 text-sm font-semibold tracking-wider uppercase">
          Loading Security Service Metadata...
        </p>
      </div>
    );
  }

  if (errorMessage || !service) {
    return (
      <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center text-white p-6">
        <AlertTriangle className="w-16 h-16 text-amber-500 mb-4" />
        <h2 className="text-2xl font-bold mb-2">Service Not Found</h2>
        <p className="text-slate-400 mb-6">{errorMessage || 'Invalid service ID.'}</p>
        <button onClick={() => navigate('/dashboard')} className="btn btn-primary rounded-xl">
          Return to Dashboard
        </button>
      </div>
    );
  }

  const Icon = iconMap[service.iconKey] || ShieldAlert;

  // ── Service #1 Override: File Vulnerability & Malware Scanner ────────────────
  // Service ID 1 is repurposed from a network scanner to a full file analysis tool.
  // Instead of the socket-based execution UI, we render the dedicated FileScannerScreen.
  if (service.serviceId === 1) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100">
        {/* Navigation strip preserved for consistent UX */}
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors font-medium text-sm group"
            >
              <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
              Back to Dashboard
            </Link>
            <span className="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
              Service #{service.serviceId} · {service.name}
            </span>
          </div>
        </div>
        {/* Render the file scanner UI directly */}
        <FileScannerScreen />
      </div>
    );
  }

  // ── Service #2 Override: Phishing & Scam Detector ────────────────────────────
  // Service ID 2 renders the dedicated Phishing & Scam Detector tool.
  if (service.serviceId === 2 || (service?.name && service.name.toLowerCase().includes('phishing'))) {
    return <PhishingDetectorScreen />;
  }

  // ── Service #3 Override: Client Environment & Network Security Audit ─────────
  // Service ID 3 is the dedicated Client Environment & Network Audit tool.
  if (service?.serviceId === 3 || id === '3' || (service?.name && service.name.toLowerCase().includes('security audit'))) {
    return <ClientAuditScreen />;
  }

  // ── Service #7 Override: Password Security Lab ───────────────────────────────
  // Service ID 7 renders the dedicated Password Security Lab tool.
  if (service?.serviceId === 7 || id === '7' || (service?.name && service.name.toLowerCase().includes('password'))) {
    return <PasswordSecurityScreen />;
  }

  // ── Service #8 Override: Website Security Scanner ─────────────────────────────
  // Service ID 8 renders the dedicated Website Security Scanner tool.
  if (service?.serviceId === 8 || id === '8' || (service?.name && service.name.toLowerCase().includes('website'))) {
    return <WebsiteSecurityScreen />;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Navigation Bar & Live Status */}
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors font-medium text-sm group"
          >
            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
            Back to Dashboard
          </Link>

          {/* Socket Connection Badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                socketConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'
              }`}
            ></span>
            <span className="font-mono text-slate-300">
              {socketConnected ? 'Socket Engine: Live' : 'Connecting Engine...'}
            </span>
          </div>
        </div>

        {/* Hero Card */}
        <div className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 shadow-2xl p-6 sm:p-8">
          <div className={`absolute top-0 right-0 w-96 h-96 bg-gradient-to-br ${service.color} opacity-15 rounded-full blur-3xl pointer-events-none`}></div>

          <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="flex items-start sm:items-center gap-5">
              <div
                className={`w-16 h-16 rounded-2xl bg-gradient-to-br ${service.color} ${service.shadow} flex items-center justify-center text-white flex-shrink-0 shadow-lg`}
              >
                <Icon className="w-8 h-8" />
              </div>
              <div>
                <div className="flex items-center gap-3 flex-wrap">
                  <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
                    {service.name}
                  </h1>
                  <span
                    className={`px-3 py-0.5 rounded-full text-xs font-bold ${
                      service.status === 'Active'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}
                  >
                    {service.status}
                  </span>
                  <span className="px-2.5 py-0.5 rounded-md text-[11px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                    ID: #{service.serviceId}
                  </span>
                </div>
                <p className="text-slate-400 text-sm mt-1 max-w-2xl leading-relaxed">
                  {service.description}
                </p>
                <div className="flex items-center gap-4 mt-3 text-xs text-slate-500 font-mono">
                  <span className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    Last Run:{' '}
                    {service.lastRun ? new Date(service.lastRun).toLocaleString() : 'Never'}
                  </span>
                  <span>•</span>
                  <span>Metrics: {service.metrics}</span>
                </div>
              </div>
            </div>

            {/* Run Action Button */}
            <div className="w-full md:w-auto flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="flex gap-2 w-full sm:w-auto">
                <select
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-xl px-4 py-2 focus:ring-2 focus:ring-blue-500 outline-none flex-1 min-w-[200px]"
                >
                  {targets.length === 0 ? (
                    <option value="">No targets available</option>
                  ) : (
                    targets.map((t) => (
                      <option key={t._id} value={t._id}>
                        {t.name} ({t.host})
                      </option>
                    ))
                  )}
                </select>
                <button
                  onClick={() => setIsTargetModalOpen(true)}
                  className="btn btn-outline border-slate-700 hover:bg-slate-800 text-slate-300 rounded-xl flex items-center justify-center px-3"
                  title="Add New Target"
                >
                  <Server className="w-4 h-4" />
                  <span className="hidden sm:inline-block ml-2 text-xs">+ Add</span>
                </button>
              </div>

              <button
                onClick={handleRunService}
                disabled={isRunning || !socketConnected || !selectedTargetId}
                className={`btn btn-primary rounded-xl px-6 py-3 font-semibold text-sm shadow-xl flex items-center justify-center gap-2.5 transition-all ${
                  isRunning || !selectedTargetId
                    ? 'opacity-80 cursor-not-allowed bg-slate-800 text-slate-400 border-slate-700'
                    : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white border-none shadow-blue-600/20'
                }`}
              >
                {isRunning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
                    <span>Executing Scan ({progress}%)...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Run Service Now</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Active Progress Meter */}
          {isRunning && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="mt-6 pt-6 border-t border-slate-800"
            >
              <div className="flex justify-between items-center text-xs font-mono mb-2">
                <span className="text-blue-400 flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 animate-pulse text-blue-400" />
                  Streaming live scan telemetry via WebSocket...
                </span>
                <span className="text-slate-400">
                  Step {currentStep.step} / {currentStep.total} ({progress}%)
                </span>
              </div>
              <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden p-0.5">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  transition={{ ease: 'easeOut', duration: 0.3 }}
                  className={`h-full rounded-full bg-gradient-to-r ${service.color}`}
                ></motion.div>
              </div>
            </motion.div>
          )}
        </div>

        {/* Live Security Terminal Window */}
        <div className="rounded-3xl bg-slate-900 border border-slate-800 overflow-hidden shadow-2xl flex flex-col">
          {/* Terminal Window Header */}
          <div className="bg-slate-950 px-5 py-3 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block"></span>
              <span className="ml-3 font-mono text-xs text-slate-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                secops-term: ~/services/{service.name.toLowerCase().replace(/\s+/g, '-')}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyLogs}
                disabled={logs.length === 0}
                className="btn btn-ghost btn-xs text-slate-400 hover:text-white rounded-lg flex items-center gap-1 normal-case font-mono"
                title="Copy terminal buffer"
              >
                {copiedLogs ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied!
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" /> Copy Buffer
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Terminal Logs Output Body */}
          <div className="p-6 bg-slate-950/90 font-mono text-xs sm:text-sm h-[380px] overflow-y-auto space-y-2 select-text">
            {logs.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-600 space-y-2">
                <Terminal className="w-12 h-12 stroke-[1.5] text-slate-700" />
                <p className="text-center">Terminal session ready.</p>
                <p className="text-xs text-slate-600">
                  Click "Run Service Now" to initiate real-time socket telemetry.
                </p>
              </div>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="flex items-start gap-3 leading-relaxed break-words">
                  <span className="text-slate-600 select-none text-[11px] font-medium pt-0.5">
                    {log.timestamp}
                  </span>
                  <span
                    className={`font-semibold px-1.5 py-0.5 rounded text-[10px] select-none uppercase tracking-wider ${
                      log.level === 'ALERT'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : log.level === 'WARN'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : log.level === 'SUCCESS'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                    }`}
                  >
                    {log.level}
                  </span>
                  <span
                    className={`flex-1 ${
                      log.level === 'ALERT'
                        ? 'text-rose-300 font-semibold'
                        : log.level === 'WARN'
                        ? 'text-amber-300'
                        : log.level === 'SUCCESS'
                        ? 'text-emerald-300 font-semibold'
                        : 'text-slate-300'
                    }`}
                  >
                    {log.message}
                  </span>
                </div>
              ))
            )}

            {/* Blinking Cursor Indicator */}
            {isRunning && (
              <div className="flex items-center gap-2 pt-2 text-blue-400 font-mono">
                <span className="text-xs">&gt; [SOCKET] Awaiting next frame</span>
                <span className="inline-block w-2 h-4 bg-blue-400 animate-pulse"></span>
              </div>
            )}
            <div ref={terminalBottomRef}></div>
          </div>
        </div>

        {/* Scan Completion Report Card */}
        <AnimatePresence>
          {scanReport && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="rounded-3xl bg-slate-900 border border-slate-700/50 p-6 sm:p-8 shadow-2xl relative overflow-hidden mt-6"
            >
              <div className="absolute top-0 right-0 w-64 h-64 bg-slate-800/20 rounded-full blur-3xl pointer-events-none"></div>

              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-6 border-b border-slate-800 gap-4">
                <div className="flex items-center gap-3">
                  <div className={`w-12 h-12 rounded-2xl flex items-center justify-center ${
                    scanReport.findings?.length === 0 
                      ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400' 
                      : 'bg-amber-500/20 border-amber-500/30 text-amber-400'
                  }`}>
                    {scanReport.findings?.length === 0 ? <CheckCircle className="w-6 h-6" /> : <AlertTriangle className="w-6 h-6" />}
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-white">Execution Audit Complete</h3>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      Status: {scanReport.status}
                    </p>
                  </div>
                </div>

                <button
                  onClick={handleDownloadReport}
                  className="btn btn-outline btn-sm rounded-xl border-slate-700 hover:bg-slate-800 text-slate-300 normal-case flex items-center gap-2"
                >
                  <Download className="w-3.5 h-3.5" /> Export PDF Report
                </button>
              </div>

              {/* Findings Section */}
              <div className="mt-6">
                <h4 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-slate-400" />
                  Security Findings ({scanReport.findings?.length || 0})
                </h4>
                
                {(!scanReport.findings || scanReport.findings.length === 0) ? (
                  <div className="p-6 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-center flex flex-col items-center">
                    <CheckCircle className="w-10 h-10 text-emerald-500 mb-2" />
                    <h5 className="font-bold text-emerald-400">No vulnerabilities found.</h5>
                    <p className="text-emerald-500/70 text-sm mt-1">Ports closed and headers secure.</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {scanReport.findings.map((finding, idx) => (
                      <div key={idx} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex items-start justify-between">
                        <div>
                          <p className="font-semibold text-slate-200 text-sm">{finding.type}</p>
                          <p className="text-slate-400 text-xs mt-1">{finding.description}</p>
                        </div>
                        <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold tracking-wider ${
                          finding.severity === 'CRITICAL' || finding.severity === 'HIGH' 
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : finding.severity === 'MEDIUM'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}>
                          {finding.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          )}      )}
        </AnimatePresence>
      </div>

      <CreateTargetModal 
        isOpen={isTargetModalOpen} 
        onClose={() => setIsTargetModalOpen(false)} 
        onTargetCreated={(newTarget) => {
          setTargets((prev) => [newTarget, ...prev]);
          setSelectedTargetId(newTarget._id);
        }} 
      />
    </div>
  );
};

export default ServiceDetailScreen;
