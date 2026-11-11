import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../utils/api';
import {
  ArrowLeft,
  ShieldAlert,
  Search,
  Link2,
  MessageSquare,
  Mail,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  ChevronRight,
  Shield,
  Clock,
  Info,
  ExternalLink,
  HelpCircle,
} from 'lucide-react';

// ─── Constants ───────────────────────────────────────────────────────────────

const ANALYSIS_MODES = [
  {
    id: 'url',
    label: 'URL Analysis',
    icon: Link2,
    description: 'Check suspicious website links for phishing indicators',
    placeholder: 'Enter a suspicious URL (e.g., https://example.com/login)',
  },
  {
    id: 'message',
    label: 'Message Detection',
    icon: MessageSquare,
    description: 'Analyze suspicious texts, WhatsApp messages, or social media messages',
    placeholder: 'Paste the suspicious message content here...',
  },
  {
    id: 'email_sms',
    label: 'Email / SMS Analysis',
    icon: Mail,
    description: 'Analyze email or SMS content with optional sender verification',
    placeholder: 'Paste the email or SMS content here...',
  },
];

const RISK_COLORS = {
  Low: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    fill: 'bg-emerald-500',
    glow: 'shadow-emerald-500/20',
    gradient: 'from-emerald-500 to-green-600',
    label: 'Low Risk',
  },
  Medium: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    fill: 'bg-amber-500',
    glow: 'shadow-amber-500/20',
    gradient: 'from-amber-500 to-orange-600',
    label: 'Medium Risk',
  },
  High: {
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/30',
    text: 'text-rose-400',
    fill: 'bg-rose-500',
    glow: 'shadow-rose-500/20',
    gradient: 'from-rose-500 to-red-600',
    label: 'High Risk',
  },
  Unknown: {
    bg: 'bg-slate-500/10',
    border: 'border-slate-500/30',
    text: 'text-slate-400',
    fill: 'bg-slate-500',
    glow: 'shadow-slate-500/20',
    gradient: 'from-slate-500 to-gray-600',
    label: 'Unknown',
  },
};

// ─── Risk Score Gauge Component ──────────────────────────────────────────────

const RiskScoreGauge = ({ score, riskLevel }) => {
  const colors = RISK_COLORS[riskLevel] || RISK_COLORS.Unknown;
  const circumference = 2 * Math.PI * 54;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="relative w-40 h-40 mx-auto">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
        {/* Background circle */}
        <circle
          cx="60" cy="60" r="54"
          stroke="currentColor"
          strokeWidth="8"
          fill="none"
          className="text-slate-800"
        />
        {/* Animated score arc */}
        <motion.circle
          cx="60" cy="60" r="54"
          stroke="url(#scoreGradient)"
          strokeWidth="8"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1.2, ease: 'easeOut', delay: 0.3 }}
        />
        <defs>
          <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            {riskLevel === 'High' && (
              <>
                <stop offset="0%" stopColor="#f43f5e" />
                <stop offset="100%" stopColor="#ef4444" />
              </>
            )}
            {riskLevel === 'Medium' && (
              <>
                <stop offset="0%" stopColor="#f59e0b" />
                <stop offset="100%" stopColor="#f97316" />
              </>
            )}
            {(riskLevel === 'Low' || !riskLevel) && (
              <>
                <stop offset="0%" stopColor="#10b981" />
                <stop offset="100%" stopColor="#22c55e" />
              </>
            )}
            {riskLevel === 'Unknown' && (
              <>
                <stop offset="0%" stopColor="#64748b" />
                <stop offset="100%" stopColor="#6b7280" />
              </>
            )}
          </linearGradient>
        </defs>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className={`text-3xl font-black ${colors.text}`}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.5 }}
        >
          {score}
        </motion.span>
        <span className="text-xs text-slate-500 font-semibold mt-1">/ 100</span>
      </div>
    </div>
  );
};

// ─── Warning Sign Card Component ─────────────────────────────────────────────

const WarningSignCard = ({ warning, index }) => {
  const severityColors = {
    low: 'border-blue-500/30 bg-blue-500/5',
    medium: 'border-amber-500/30 bg-amber-500/5',
    high: 'border-rose-500/30 bg-rose-500/5',
  };

  const severityBadgeColors = {
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    high: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.1 * index }}
      className={`p-4 rounded-xl border ${severityColors[warning.severity]} transition-all hover:scale-[1.01]`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${
              warning.severity === 'high' ? 'text-rose-400' :
              warning.severity === 'medium' ? 'text-amber-400' : 'text-blue-400'
            }`} />
            <span className="font-bold text-sm text-slate-200">{warning.indicator}</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">{warning.description}</p>
        </div>
        <span className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wider border flex-shrink-0 ${severityBadgeColors[warning.severity]}`}>
          {warning.severity}
        </span>
      </div>
    </motion.div>
  );
};

// ─── Main Component ──────────────────────────────────────────────────────────

const PhishingDetectorScreen = () => {
  const navigate = useNavigate();

  // State
  const [activeMode, setActiveMode] = useState('url');
  const [inputValue, setInputValue] = useState('');
  const [senderInfo, setSenderInfo] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const currentMode = ANALYSIS_MODES.find(m => m.id === activeMode);

  // Handle mode switch
  const handleModeChange = useCallback((modeId) => {
    setActiveMode(modeId);
    setInputValue('');
    setSenderInfo('');
    setResult(null);
    setError('');
  }, []);

  // Validate input
  const validateInput = useCallback(() => {
    if (!inputValue.trim()) {
      setError('Please enter content to analyze.');
      return false;
    }

    if (activeMode === 'url') {
      if (inputValue.trim().length < 4) {
        setError('Please enter a valid URL.');
        return false;
      }
      // Check for dangerous protocols
      const trimmed = inputValue.trim().toLowerCase();
      const dangerousProtocols = ['data:', 'vbscript:'];
      // eslint-disable-next-line no-script-url
      dangerousProtocols.push('javascript:');
      if (dangerousProtocols.some(p => trimmed.startsWith(p))) {
        setError('Only HTTP and HTTPS URLs are supported.');
        return false;
      }
    }

    if (activeMode !== 'url' && inputValue.trim().length < 10) {
      setError('Please enter a longer message for meaningful analysis (at least 10 characters).');
      return false;
    }

    return true;
  }, [inputValue, activeMode]);

  // Submit analysis
  const handleAnalyze = useCallback(async () => {
    setError('');
    setResult(null);

    if (!validateInput()) return;

    setIsAnalyzing(true);

    try {
      let response;

      if (activeMode === 'url') {
        response = await api.post('/phishing/analyze-url', {
          url: inputValue.trim(),
        });
      } else {
        response = await api.post('/phishing/analyze-message', {
          message: inputValue.trim(),
          senderInfo: senderInfo.trim() || undefined,
          analysisType: activeMode,
        });
      }

      if (response.data?.success && response.data?.result) {
        setResult(response.data.result);
      } else {
        setError('Unexpected response format from analysis service.');
      }
    } catch (err) {
      console.error('Analysis failed:', err);
      if (err.response?.status === 429) {
        setError('Rate limit exceeded. Please wait a moment before trying again.');
      } else if (err.response?.data?.error) {
        setError(err.response.data.error);
      } else if (err.code === 'ECONNABORTED') {
        setError('Analysis request timed out. Please try again.');
      } else {
        setError('Failed to connect to the analysis service. Please check your connection and try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  }, [activeMode, inputValue, senderInfo, validateInput]);

  // Reset for new analysis
  const handleReset = useCallback(() => {
    setInputValue('');
    setSenderInfo('');
    setResult(null);
    setError('');
  }, []);

  // Handle Enter key in URL mode
  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Enter' && activeMode === 'url' && !isAnalyzing) {
      e.preventDefault();
      handleAnalyze();
    }
  }, [activeMode, isAnalyzing, handleAnalyze]);

  const riskColors = result ? (RISK_COLORS[result.riskLevel] || RISK_COLORS.Unknown) : null;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Navigation Header */}
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <button
            onClick={() => navigate('/dashboard')}
            className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors font-medium text-sm group"
          >
            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
            Back to Dashboard
          </button>
          <span className="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
            Service #2 · Phishing & Scam Detector
          </span>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Hero Section */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-3xl bg-slate-900 border border-slate-800 shadow-2xl p-6 sm:p-8"
        >
          <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-orange-500 to-red-600 opacity-10 rounded-full blur-3xl pointer-events-none"></div>

          <div className="relative z-10 flex items-start gap-5">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-orange-500 to-red-600 shadow-lg shadow-orange-500/30 flex items-center justify-center text-white flex-shrink-0">
              <ShieldAlert className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
                Phishing & Scam Detector
              </h1>
              <p className="text-slate-400 text-sm mt-2 max-w-2xl leading-relaxed">
                Analyze suspicious URLs, emails, SMS messages, and online messages to identify phishing indicators,
                potential scams, and recommended safety actions. Select an analysis mode below.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Analysis Mode Tabs */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {ANALYSIS_MODES.map((mode) => {
            const ModeIcon = mode.icon;
            const isActive = activeMode === mode.id;

            return (
              <motion.button
                key={mode.id}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => handleModeChange(mode.id)}
                className={`relative p-4 rounded-2xl border transition-all text-left ${
                  isActive
                    ? 'bg-gradient-to-br from-orange-500/10 to-red-500/10 border-orange-500/40 shadow-lg shadow-orange-500/10'
                    : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                    isActive
                      ? 'bg-gradient-to-br from-orange-500 to-red-600 text-white'
                      : 'bg-slate-800 text-slate-400'
                  }`}>
                    <ModeIcon className="w-5 h-5" />
                  </div>
                  <span className={`font-bold text-sm ${isActive ? 'text-white' : 'text-slate-300'}`}>
                    {mode.label}
                  </span>
                </div>
                <p className="text-xs text-slate-500 leading-relaxed">{mode.description}</p>
                {isActive && (
                  <motion.div
                    layoutId="activeModeBorder"
                    className="absolute bottom-0 left-4 right-4 h-0.5 bg-gradient-to-r from-orange-500 to-red-600 rounded-full"
                  />
                )}
              </motion.button>
            );
          })}
        </div>

        {/* Input Section */}
        <AnimatePresence mode="wait">
          {!result && (
            <motion.div
              key="input-form"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="bg-slate-900 rounded-3xl border border-slate-800 p-6 sm:p-8 shadow-2xl"
            >
              {/* URL Input Mode */}
              {activeMode === 'url' && (
                <div className="space-y-4">
                  <label className="block text-sm font-bold text-slate-300">
                    <Link2 className="w-4 h-4 inline-block mr-2 text-orange-400" />
                    Suspicious URL
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={inputValue}
                      onChange={(e) => { setInputValue(e.target.value); setError(''); }}
                      onKeyDown={handleKeyDown}
                      placeholder={currentMode.placeholder}
                      className="w-full bg-slate-950 border border-slate-700 rounded-xl px-5 py-4 text-sm text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-orange-500/50 focus:border-orange-500/50 outline-none transition-all font-mono"
                      maxLength={2048}
                      disabled={isAnalyzing}
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <ExternalLink className="w-4 h-4 absolute right-4 top-1/2 -translate-y-1/2 text-slate-600" />
                  </div>
                  <p className="text-xs text-slate-600 flex items-center gap-1.5">
                    <Info className="w-3 h-3" />
                    URLs are analyzed for patterns only. They are never visited or downloaded.
                  </p>
                </div>
              )}

              {/* Message / Email-SMS Input Mode */}
              {(activeMode === 'message' || activeMode === 'email_sms') && (
                <div className="space-y-4">
                  {/* Sender Info (email_sms only) */}
                  {activeMode === 'email_sms' && (
                    <div>
                      <label className="block text-sm font-bold text-slate-300 mb-2">
                        <Mail className="w-4 h-4 inline-block mr-2 text-orange-400" />
                        Sender Address / Phone (Optional)
                      </label>
                      <input
                        type="text"
                        value={senderInfo}
                        onChange={(e) => setSenderInfo(e.target.value)}
                        placeholder="e.g., sender@example.com or +1234567890"
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl px-5 py-3 text-sm text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-orange-500/50 focus:border-orange-500/50 outline-none transition-all"
                        maxLength={320}
                        disabled={isAnalyzing}
                        autoComplete="off"
                      />
                    </div>
                  )}

                  <div>
                    <label className="block text-sm font-bold text-slate-300 mb-2">
                      <MessageSquare className="w-4 h-4 inline-block mr-2 text-orange-400" />
                      {activeMode === 'email_sms' ? 'Email / SMS Content' : 'Message Content'}
                    </label>
                    <textarea
                      value={inputValue}
                      onChange={(e) => { setInputValue(e.target.value); setError(''); }}
                      placeholder={currentMode.placeholder}
                      rows={8}
                      className="w-full bg-slate-950 border border-slate-700 rounded-xl px-5 py-4 text-sm text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-orange-500/50 focus:border-orange-500/50 outline-none transition-all resize-y min-h-[120px] max-h-[400px]"
                      maxLength={10000}
                      disabled={isAnalyzing}
                      spellCheck={false}
                    />
                    <div className="flex items-center justify-between mt-1">
                      <p className="text-xs text-slate-600 flex items-center gap-1.5">
                        <Info className="w-3 h-3" />
                        {activeMode === 'email_sms'
                          ? 'Do not include passwords, OTPs, or sensitive credentials.'
                          : 'Paste the full suspicious message for best results.'}
                      </p>
                      <span className="text-xs text-slate-600 font-mono">
                        {inputValue.length}/10000
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Error Display */}
              <AnimatePresence>
                {error && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-4 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-sm flex items-center gap-3"
                  >
                    <XCircle className="w-5 h-5 flex-shrink-0" />
                    <span>{error}</span>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Analyze Button */}
              <div className="mt-6 flex flex-col sm:flex-row items-stretch sm:items-center gap-4">
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || !inputValue.trim()}
                  className={`flex-1 sm:flex-none px-8 py-4 rounded-xl font-bold text-sm flex items-center justify-center gap-3 transition-all shadow-xl ${
                    isAnalyzing || !inputValue.trim()
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                      : 'bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-400 hover:to-red-500 text-white shadow-orange-500/20 hover:shadow-orange-500/30'
                  }`}
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-5 h-5 animate-spin" />
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      <span>Analyze {activeMode === 'url' ? 'URL' : 'Message'}</span>
                    </>
                  )}
                </button>

                {inputValue && (
                  <button
                    onClick={handleReset}
                    disabled={isAnalyzing}
                    className="px-6 py-4 rounded-xl font-semibold text-sm text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-all"
                  >
                    Clear
                  </button>
                )}
              </div>

              {/* Disclaimer */}
              <div className="mt-6 p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-2.5">
                <HelpCircle className="w-4 h-4 text-slate-600 flex-shrink-0 mt-0.5" />
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  <strong className="text-slate-500">Disclaimer:</strong> No automated detection system can guarantee that a URL or message is safe. 
                  Results represent observed risk indicators based on known patterns — not a verified probability of malicious intent. 
                  Always exercise personal judgment.
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Loading State */}
        <AnimatePresence>
          {isAnalyzing && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-slate-900 rounded-3xl border border-slate-800 p-12 shadow-2xl flex flex-col items-center justify-center"
            >
              <div className="relative">
                <div className="w-20 h-20 border-4 border-slate-800 border-t-orange-500 rounded-full animate-spin"></div>
                <Shield className="w-8 h-8 text-orange-500 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
              </div>
              <p className="mt-6 text-slate-400 font-semibold text-sm">Analyzing for phishing indicators...</p>
              <p className="mt-2 text-slate-600 text-xs">Checking patterns, domain reputation, and content signatures</p>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results Section */}
        <AnimatePresence>
          {result && !isAnalyzing && (
            <motion.div
              key="results"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -30 }}
              transition={{ duration: 0.4 }}
              className="space-y-6"
            >
              {/* Risk Score Overview Card */}
              <div className={`bg-slate-900 rounded-3xl border ${riskColors.border} p-6 sm:p-8 shadow-2xl relative overflow-hidden`}>
                <div className={`absolute top-0 right-0 w-80 h-80 bg-gradient-to-br ${riskColors.gradient} opacity-5 rounded-full blur-3xl pointer-events-none`}></div>

                <div className="relative z-10 grid grid-cols-1 md:grid-cols-3 gap-8 items-center">
                  {/* Score Gauge */}
                  <div className="flex flex-col items-center">
                    <RiskScoreGauge score={result.riskScore} riskLevel={result.riskLevel} />
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.8 }}
                      className={`mt-4 px-5 py-2 rounded-full font-bold text-sm ${riskColors.bg} ${riskColors.text} border ${riskColors.border}`}
                    >
                      {riskColors.label}
                    </motion.div>
                  </div>

                  {/* Summary */}
                  <div className="md:col-span-2 space-y-4">
                    <div>
                      <h3 className="text-xl font-bold text-white flex items-center gap-2 mb-2">
                        {result.riskLevel === 'High' && <XCircle className="w-6 h-6 text-rose-400" />}
                        {result.riskLevel === 'Medium' && <AlertTriangle className="w-6 h-6 text-amber-400" />}
                        {result.riskLevel === 'Low' && <CheckCircle className="w-6 h-6 text-emerald-400" />}
                        {result.riskLevel === 'Unknown' && <HelpCircle className="w-6 h-6 text-slate-400" />}
                        Detection Summary
                      </h3>
                      <p className="text-slate-400 text-sm leading-relaxed">{result.summary}</p>
                    </div>

                    {/* Analysis Metadata */}
                    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 font-mono">
                      <span className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(result.analysisTimestamp).toLocaleString()}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5" />
                        Type: {result.analysisType === 'url' ? 'URL Analysis' : result.analysisType === 'email_sms' ? 'Email/SMS Analysis' : 'Message Analysis'}
                      </span>
                    </div>

                    {/* Input Preview */}
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="text-[10px] uppercase tracking-wider text-slate-600 font-bold">Analyzed Content</span>
                      <p className="text-xs text-slate-400 mt-1 font-mono break-all">{result.inputPreview}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Warning Signs */}
              {result.warningSignsDetected && result.warningSignsDetected.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="bg-slate-900 rounded-3xl border border-slate-800 p-6 sm:p-8 shadow-2xl"
                >
                  <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-amber-400" />
                    Warning Signs Detected ({result.warningSignsDetected.length})
                  </h3>
                  <div className="space-y-3">
                    {result.warningSignsDetected.map((warning, idx) => (
                      <WarningSignCard key={idx} warning={warning} index={idx} />
                    ))}
                  </div>
                </motion.div>
              )}

              {/* No Warnings */}
              {result.warningSignsDetected && result.warningSignsDetected.length === 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="bg-slate-900 rounded-3xl border border-emerald-500/20 p-8 shadow-2xl text-center"
                >
                  <CheckCircle className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
                  <h4 className="font-bold text-emerald-400 text-lg">No Suspicious Indicators Detected</h4>
                  <p className="text-emerald-500/60 text-sm mt-2 max-w-md mx-auto">
                    No known phishing or scam patterns were identified. However, this does <strong>not</strong> confirm the content is safe or legitimate.
                  </p>
                </motion.div>
              )}

              {/* Recommended Actions */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="bg-slate-900 rounded-3xl border border-slate-800 p-6 sm:p-8 shadow-2xl"
              >
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-blue-400" />
                  Recommended Actions
                </h3>
                <div className="space-y-3">
                  {result.recommendedActions.map((action, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.4 + idx * 0.1 }}
                      className="flex items-start gap-3 p-3 rounded-lg bg-slate-950/60 border border-slate-800"
                    >
                      <ChevronRight className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                      <p className="text-sm text-slate-300 leading-relaxed">{action}</p>
                    </motion.div>
                  ))}
                </div>
              </motion.div>

              {/* Limitations */}
              {result.limitations && result.limitations.length > 0 && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 }}
                  className="bg-slate-900/50 rounded-2xl border border-slate-800 p-5"
                >
                  <h4 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                    <Info className="w-4 h-4" />
                    Analysis Limitations
                  </h4>
                  <ul className="space-y-2">
                    {result.limitations.map((limitation, idx) => (
                      <li key={idx} className="text-xs text-slate-500 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-slate-600 flex-shrink-0 mt-1.5"></span>
                        {limitation}
                      </li>
                    ))}
                  </ul>
                </motion.div>
              )}

              {/* Disclaimer Footer */}
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-2.5">
                <HelpCircle className="w-4 h-4 text-slate-600 flex-shrink-0 mt-0.5" />
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  {result.disclaimer}
                </p>
              </div>

              {/* Analyze Another Button */}
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <motion.button
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.97 }}
                  onClick={handleReset}
                  className="px-8 py-4 rounded-xl font-bold text-sm bg-gradient-to-r from-orange-500 to-red-600 text-white shadow-xl shadow-orange-500/20 hover:shadow-orange-500/30 flex items-center gap-3 transition-all"
                >
                  <RefreshCw className="w-5 h-5" />
                  Analyze Another
                </motion.button>
                <button
                  onClick={() => navigate('/dashboard')}
                  className="px-6 py-4 rounded-xl font-semibold text-sm text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-all"
                >
                  Return to Dashboard
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default PhishingDetectorScreen;
