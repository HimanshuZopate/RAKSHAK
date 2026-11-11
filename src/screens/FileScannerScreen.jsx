import React, { useState, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import {
  ShieldAlert,
  Upload,
  FileText,
  CheckCircle,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Cpu,
  Lock,
  Globe,
  Code,
  Key,
  Activity,
  RotateCcw,
  FileSearch,
  Zap,
} from 'lucide-react';

// ── Constants ──────────────────────────────────────────────────────────────────
const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/30',
    text: 'text-rose-400',
    badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
  },
  HIGH: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  },
  MEDIUM: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  },
  LOW: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    text: 'text-blue-400',
    badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  },
  INFO: {
    bg: 'bg-slate-500/10',
    border: 'border-slate-600/30',
    text: 'text-slate-400',
    badge: 'bg-slate-700/50 text-slate-400 border-slate-600/40',
  },
};

const STATUS_CONFIG = {
  Clean: {
    banner: 'bg-emerald-500/10 border-emerald-500/30',
    icon: CheckCircle,
    iconColor: 'text-emerald-400',
    title: 'File is Clean',
    titleColor: 'text-emerald-300',
    pulse: 'bg-emerald-400',
  },
  Suspicious: {
    banner: 'bg-amber-500/10 border-amber-500/30',
    icon: AlertTriangle,
    iconColor: 'text-amber-400',
    title: 'Suspicious File Detected',
    titleColor: 'text-amber-300',
    pulse: 'bg-amber-400',
  },
  Malicious: {
    banner: 'bg-rose-500/10 border-rose-500/30',
    icon: XCircle,
    iconColor: 'text-rose-400',
    title: 'Malicious File Detected!',
    titleColor: 'text-rose-300',
    pulse: 'bg-rose-500',
  },
};

const CATEGORY_ICON_MAP = {
  'Malware Signature': ShieldAlert,
  'Malicious Macro': Code,
  'Dangerous Code Pattern': Zap,
  'Obfuscation Technique': Lock,
  'External URL': Globe,
  'Hardcoded Private IP': Activity,
  'Hardcoded Public IP': Activity,
  'Exposed Credential': Key,
  'Hardcoded Secret': Key,
  'Possible AWS Secret Key': Key,
  'Engine Status': Cpu,
  'Extraction Error': FileText,
};

/** Generate dynamic remediation suggestions based on finding categories */
function buildRemediation(findings, status) {
  const categories = new Set(findings.map((f) => f.category));
  const suggestions = [];

  if (status === 'Malicious') {
    suggestions.push('⛔ Do NOT execute, open, or share this file. Quarantine it immediately.');
  }
  if (categories.has('Malware Signature')) {
    suggestions.push('🦠 ClamAV detected a known malware signature. Delete the file and scan the source system.');
  }
  if (categories.has('Malicious Macro')) {
    suggestions.push('📎 Auto-executing macros found — a hallmark of Office dropper malware. Never enable macros from untrusted files.');
  }
  if (categories.has('Dangerous Code Pattern') || categories.has('Obfuscation Technique')) {
    suggestions.push('⚙️ Obfuscated or dangerous execution patterns detected. This file may be a script-based dropper or RAT payload.');
  }
  if (categories.has('Exposed Credential') || categories.has('Hardcoded Secret') || categories.has('Possible AWS Secret Key')) {
    suggestions.push('🔑 Hardcoded credentials or API keys were found. Rotate affected keys immediately and audit your secrets management practices.');
  }
  if (categories.has('External URL')) {
    suggestions.push('🌐 External URLs found. Verify each URL against threat intelligence feeds before accessing.');
  }
  if (categories.has('Hardcoded Private IP') || categories.has('Hardcoded Public IP')) {
    suggestions.push('📡 Hardcoded IP addresses detected. These may indicate C2 server callbacks or data exfiltration endpoints.');
  }
  if (status === 'Clean') {
    suggestions.push('✅ No threats detected. The file appears safe based on signature and static analysis.');
    suggestions.push('💡 Tip: For maximum safety, always scan files in a sandboxed environment before execution.');
  }

  return suggestions;
}

// ── Component: Findings Table ──────────────────────────────────────────────────
function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) return null;

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-700/50">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-slate-800/80 text-slate-400 text-xs uppercase tracking-wider">
            <th className="px-4 py-3 text-left">Engine</th>
            <th className="px-4 py-3 text-left">Category</th>
            <th className="px-4 py-3 text-left">Detail</th>
            <th className="px-4 py-3 text-left">Severity</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {findings.map((finding, idx) => {
            const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.INFO;
            const CategoryIcon = CATEGORY_ICON_MAP[finding.category] || ShieldAlert;

            return (
              <motion.tr
                key={idx}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.04 }}
                className={`${cfg.bg} transition-colors`}
              >
                <td className="px-4 py-3 whitespace-nowrap">
                  <span className="flex items-center gap-1.5 font-mono text-xs font-semibold text-slate-300">
                    <Cpu className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />
                    {finding.engine}
                  </span>
                </td>
                <td className="px-4 py-3 whitespace-nowrap">
                  <span className="flex items-center gap-1.5 text-slate-300 font-medium text-xs">
                    <CategoryIcon className={`w-3.5 h-3.5 flex-shrink-0 ${cfg.text}`} />
                    {finding.category}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-400 text-xs max-w-xs">
                  <span className="block truncate" title={finding.detail}>
                    {finding.detail}
                  </span>
                </td>
                <td className="px-4 py-3 whitespace-nowrap">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider border ${cfg.badge}`}>
                    {finding.severity}
                  </span>
                </td>
              </motion.tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Component: Scan Report ─────────────────────────────────────────────────────
function ScanReport({ result, onReset }) {
  const cfg = STATUS_CONFIG[result.status] || STATUS_CONFIG.Suspicious;
  const StatusIcon = cfg.icon;
  const remediation = buildRemediation(result.findings, result.status);

  const criticalCount = result.findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = result.findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = result.findings.filter((f) => f.severity === 'MEDIUM').length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -24 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
      className="space-y-5"
    >
      {/* ── Hero Status Banner ── */}
      <div className={`rounded-2xl border p-5 ${cfg.banner} flex items-center gap-4`}>
        <div className="relative flex-shrink-0">
          <StatusIcon className={`w-12 h-12 ${cfg.iconColor}`} />
          <span className={`absolute top-0 right-0 w-3 h-3 rounded-full ${cfg.pulse} animate-ping`} />
          <span className={`absolute top-0 right-0 w-3 h-3 rounded-full ${cfg.pulse}`} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className={`text-xl font-black tracking-tight ${cfg.titleColor}`}>{cfg.title}</h3>
          <p className="text-slate-400 text-sm mt-0.5 leading-snug">{result.summary}</p>
        </div>
        <div className="hidden sm:flex flex-col items-end gap-1 text-xs font-mono text-slate-500 flex-shrink-0">
          <span>{result.fileName}</span>
          <span>{(result.fileSize / 1024).toFixed(1)} KB</span>
          <span>
            {new Date(result.scannedAt).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* ── Severity Summary Stats ── */}
      {result.findings.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Critical', count: criticalCount, color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/20' },
            { label: 'High', count: highCount, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
            { label: 'Medium', count: mediumCount, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
          ].map(({ label, count, color, bg }) => (
            <div key={label} className={`rounded-xl border p-3 text-center ${bg}`}>
              <div className={`text-2xl font-black ${color}`}>{count}</div>
              <div className="text-xs text-slate-500 font-medium uppercase tracking-wider mt-0.5">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Findings Table ── */}
      <div>
        <h4 className="text-sm font-bold text-slate-300 mb-3 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-slate-400" />
          Threat Findings ({result.findings.length})
        </h4>
        {result.findings.length === 0 ? (
          <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-6 text-center">
            <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            <p className="text-emerald-400 font-semibold">No threats detected</p>
            <p className="text-slate-500 text-xs mt-1">File passed all signature and static analysis checks.</p>
          </div>
        ) : (
          <FindingsTable findings={result.findings} />
        )}
      </div>

      {/* ── Remediation Suggestions ── */}
      <div className="rounded-2xl border border-indigo-500/20 bg-indigo-500/5 p-5">
        <h4 className="text-sm font-bold text-indigo-300 mb-3 flex items-center gap-2">
          <Lock className="w-4 h-4" />
          Remediation & Recommendations
        </h4>
        <ul className="space-y-2">
          {remediation.map((tip, i) => (
            <li key={i} className="text-slate-300 text-sm leading-snug pl-1">
              {tip}
            </li>
          ))}
        </ul>
      </div>

      {/* ── Reset Button ── */}
      <button
        onClick={onReset}
        className="w-full btn bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl flex items-center justify-center gap-2 py-3 transition-all font-semibold"
      >
        <RotateCcw className="w-4 h-4" />
        Scan Another File
      </button>
    </motion.div>
  );
}

// ── Main Component: FileScannerScreen ─────────────────────────────────────────
const FileScannerScreen = () => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState('');
  const [scanProgress, setScanProgress] = useState(0);

  const fileInputRef = useRef(null);
  const progressIntervalRef = useRef(null);

  // Accepted file types (mirrors backend)
  const ACCEPTED_TYPES = '.doc,.docx,.ppt,.pptx,.xls,.xlsx,.pdf,.txt,.html,.css,.js,.ts,.jsx,.tsx,.json,.xml,.yml,.yaml,.py,.java,.c,.cpp,.h,.cs,.go,.rb,.php,.sh,.bash,.ps1,.md';

  // ── Drag-and-Drop Handlers ────────────────────────────────────────────────
  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleFileInputChange = (e) => {
    const file = e.target.files[0];
    if (file) handleFileSelect(file);
  };

  const handleFileSelect = (file) => {
    setScanError('');
    setScanResult(null);

    // Client-side size guard (15 MB)
    if (file.size > 15 * 1024 * 1024) {
      setScanError('File exceeds 15MB limit. Please select a smaller file.');
      return;
    }

    setSelectedFile(file);
  };

  // ── Simulate visual progress (real scanning is async) ─────────────────────
  const startProgressSimulation = () => {
    setScanProgress(0);
    let progress = 0;
    progressIntervalRef.current = setInterval(() => {
      progress += Math.random() * 8;
      if (progress >= 92) {
        clearInterval(progressIntervalRef.current);
        setScanProgress(92);
        return;
      }
      setScanProgress(Math.round(progress));
    }, 300);
  };

  const finishProgress = () => {
    clearInterval(progressIntervalRef.current);
    setScanProgress(100);
  };

  // ── Submit file to backend ─────────────────────────────────────────────────
  const handleScan = async () => {
    if (!selectedFile || isScanning) return;

    setIsScanning(true);
    setScanError('');
    setScanResult(null);
    startProgressSimulation();

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await axios.post(`${API_BASE}/scanners/analyze-file`, formData, {
        withCredentials: true,
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 90000, // 90s for large files
      });

      finishProgress();
      setScanResult(res.data);
    } catch (err) {
      finishProgress();
      const msg =
        err.response?.data?.error ||
        (err.code === 'ECONNABORTED' ? 'Scan timed out. File may be too complex.' : 'Scan failed. Please try again.');
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleReset = () => {
    setScanResult(null);
    setSelectedFile(null);
    setScanError('');
    setScanProgress(0);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // ── File size formatter ────────────────────────────────────────────────────
  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 py-10 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto">

        {/* ── Page Header ── */}
        <motion.div
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-10"
        >
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500 to-rose-600 shadow-lg shadow-red-500/30 mb-4">
            <FileSearch className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-black text-white tracking-tight">
            File Vulnerability &amp; Malware Scanner
          </h1>
          <p className="text-slate-400 mt-2 text-sm max-w-xl mx-auto leading-relaxed">
            Upload a file to run a dual-engine analysis: ClamAV signature scanning for known malware,
            combined with deep static analysis for obfuscated code, embedded URLs, and exposed secrets.
          </p>
          {/* Engine Badges */}
          <div className="flex items-center justify-center gap-3 mt-4 flex-wrap">
            {[
              { label: 'ClamAV Engine', color: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
              { label: 'Static Analysis', color: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
              { label: 'Max 15MB', color: 'bg-slate-700/50 text-slate-400 border-slate-600/30' },
            ].map(({ label, color }) => (
              <span key={label} className={`px-3 py-1 rounded-full text-xs font-semibold border ${color}`}>
                {label}
              </span>
            ))}
          </div>
        </motion.div>

        <AnimatePresence mode="wait">
          {/* ── RESULT VIEW ── */}
          {scanResult ? (
            <ScanReport key="result" result={scanResult} onReset={handleReset} />
          ) : (
            /* ── UPLOAD VIEW ── */
            <motion.div
              key="upload"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-5"
            >
              {/* ── Drag and Drop Zone ── */}
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => !isScanning && fileInputRef.current?.click()}
                className={`
                  relative rounded-3xl border-2 border-dashed p-10 sm:p-14 text-center transition-all cursor-pointer select-none
                  ${isDragging
                    ? 'border-red-500/60 bg-red-500/5 scale-[1.01]'
                    : selectedFile
                    ? 'border-blue-500/40 bg-blue-500/5'
                    : 'border-slate-700 hover:border-slate-500 bg-slate-900/50 hover:bg-slate-900/80'
                  }
                  ${isScanning ? 'pointer-events-none' : ''}
                `}
              >
                {/* Background gradient glow */}
                <div className="absolute inset-0 rounded-3xl bg-gradient-to-br from-red-500/5 via-transparent to-indigo-500/5 pointer-events-none" />

                <AnimatePresence mode="wait">
                  {isScanning ? (
                    /* ── Scanning State ── */
                    <motion.div
                      key="scanning"
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0 }}
                      className="relative z-10 space-y-4"
                    >
                      <div className="relative mx-auto w-20 h-20">
                        <div className="absolute inset-0 rounded-full border-4 border-slate-700" />
                        <div className="absolute inset-0 rounded-full border-4 border-t-red-500 border-r-rose-400 border-b-transparent border-l-transparent animate-spin" />
                        <div className="absolute inset-2 rounded-full border-2 border-t-blue-400 border-transparent animate-spin" style={{ animationDuration: '1.5s', animationDirection: 'reverse' }} />
                        <div className="absolute inset-0 flex items-center justify-center">
                          <ShieldAlert className="w-7 h-7 text-red-400" />
                        </div>
                      </div>
                      <div>
                        <p className="text-white font-bold text-lg">Analyzing file signatures and heuristics...</p>
                        <p className="text-slate-400 text-sm mt-1">Running ClamAV + Static Analysis concurrently</p>
                      </div>
                      {/* Progress Bar */}
                      <div className="max-w-sm mx-auto">
                        <div className="flex justify-between text-xs font-mono text-slate-400 mb-1.5">
                          <span>Scan Progress</span>
                          <span>{scanProgress}%</span>
                        </div>
                        <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden">
                          <motion.div
                            animate={{ width: `${scanProgress}%` }}
                            transition={{ ease: 'easeOut', duration: 0.4 }}
                            className="h-full rounded-full bg-gradient-to-r from-red-500 via-rose-500 to-pink-400"
                          />
                        </div>
                        <div className="flex justify-between text-[10px] text-slate-600 mt-1.5">
                          <span>Signature DB</span>
                          <span>Heuristics</span>
                          <span>Static Rules</span>
                        </div>
                      </div>
                    </motion.div>
                  ) : selectedFile ? (
                    /* ── File Selected State ── */
                    <motion.div
                      key="selected"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0 }}
                      className="relative z-10 space-y-2"
                    >
                      <div className="w-14 h-14 mx-auto rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                        <FileText className="w-7 h-7 text-blue-400" />
                      </div>
                      <p className="text-white font-semibold text-base truncate px-4">{selectedFile.name}</p>
                      <p className="text-slate-400 text-sm">{formatSize(selectedFile.size)}</p>
                      <p className="text-slate-500 text-xs mt-2">Click to change file or drop a new one</p>
                    </motion.div>
                  ) : (
                    /* ── Default Drop Zone ── */
                    <motion.div
                      key="default"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="relative z-10 space-y-3"
                    >
                      <div className="w-16 h-16 mx-auto rounded-2xl bg-slate-800 border border-slate-700 flex items-center justify-center">
                        <Upload className="w-8 h-8 text-slate-400" />
                      </div>
                      <div>
                        <p className="text-white font-semibold text-base">
                          {isDragging ? 'Release to upload' : 'Drag & drop your file here'}
                        </p>
                        <p className="text-slate-400 text-sm mt-1">or click to browse</p>
                      </div>
                      <p className="text-slate-600 text-xs">
                        Supports: Word, PPT, Excel, PDF, Text, Code files · Max 15MB
                      </p>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Hidden file input fallback */}
                <input
                  ref={fileInputRef}
                  id="file-scanner-input"
                  type="file"
                  accept={ACCEPTED_TYPES}
                  onChange={handleFileInputChange}
                  className="hidden"
                  disabled={isScanning}
                />
              </div>

              {/* ── Error Alert ── */}
              <AnimatePresence>
                {scanError && (
                  <motion.div
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="flex items-start gap-3 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-sm"
                  >
                    <XCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                    <span>{scanError}</span>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* ── Scan Action Button ── */}
              <motion.button
                onClick={handleScan}
                disabled={!selectedFile || isScanning}
                whileHover={!selectedFile || isScanning ? {} : { scale: 1.01 }}
                whileTap={!selectedFile || isScanning ? {} : { scale: 0.99 }}
                id="file-scan-submit-btn"
                className={`
                  w-full py-4 rounded-2xl font-bold text-base flex items-center justify-center gap-2.5 transition-all
                  ${selectedFile && !isScanning
                    ? 'bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white shadow-xl shadow-red-900/40'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  }
                `}
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    Scanning in progress...
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-5 h-5" />
                    Analyze File for Threats
                  </>
                )}
              </motion.button>

              {/* ── Security Assurance Note ── */}
              <p className="text-center text-slate-600 text-xs leading-relaxed">
                <Lock className="w-3.5 h-3.5 inline mr-1 mb-0.5" />
                Files are scanned in an isolated temp directory and permanently deleted from the server
                immediately after scanning — never stored or logged.
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default FileScannerScreen;
