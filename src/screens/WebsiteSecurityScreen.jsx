import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../utils/api';
import {
  Globe,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowLeft,
  Search,
  RefreshCw,
  Lock,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Info,
  Server,
  FileText,
  Clock,
  Sparkles,
  KeyRound,
  Layers,
  Check,
  Copy,
} from 'lucide-react';

const STATUS_BADGE = {
  green: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    icon: CheckCircle2,
    label: 'Expected',
  },
  amber: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    icon: AlertTriangle,
    label: 'Needs Review',
  },
  red: {
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/30',
    text: 'text-rose-400',
    icon: XCircle,
    label: 'Issue Observed',
  },
  gray: {
    bg: 'bg-slate-500/10',
    border: 'border-slate-500/30',
    text: 'text-slate-400',
    icon: HelpCircle,
    label: 'Unable to Verify',
  },
};

const SEVERITY_BADGE = {
  Low: 'bg-slate-800 text-slate-300 border-slate-700',
  Medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  High: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  Critical: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  Informational: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
};

const WebsiteSecurityScreen = () => {
  const navigate = useNavigate();

  // URL input & execution state
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanReport, setScanReport] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [filterTab, setFilterTab] = useState('All'); // 'All' | 'Passed' | 'Needs Review' | 'Warning' | 'Unable to Verify'
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [showTlsModal, setShowTlsModal] = useState(false);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);

  // Validate URL locally before dispatch
  const handleScanSubmit = async (e) => {
    e?.preventDefault();
    setErrorMessage('');

    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setErrorMessage('Please enter a target website URL to scan.');
      return;
    }

    // Quick regex validation
    try {
      const candidate = trimmed.startsWith('http://') || trimmed.startsWith('https://')
        ? trimmed
        : `https://${trimmed}`;
      const parsed = new URL(candidate);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        setErrorMessage('Only HTTP and HTTPS protocols are supported.');
        return;
      }
      if (parsed.hostname.toLowerCase() === 'localhost' || parsed.hostname.startsWith('127.')) {
        setErrorMessage('Scanning local or private loopback addresses is restricted by SSRF protection.');
        return;
      }
    } catch {
      setErrorMessage('Please enter a valid website address (e.g., https://example.com).');
      return;
    }

    try {
      setIsScanning(true);
      setScanReport(null);

      const res = await api.post('/security/website-scan', { url: trimmed });
      if (res.data?.success && res.data?.report) {
        setScanReport(res.data.report);
      } else {
        setErrorMessage(res.data?.error || 'Scan failed to complete. Please verify the URL and try again.');
      }
    } catch (err) {
      console.error('Website scan request error:', err);
      const serverMsg = err.response?.data?.error || err.response?.data?.message || err.message;
      setErrorMessage(serverMsg || 'Unable to scan destination. Server-side connection failed or host is unreachable.');
    } finally {
      setIsScanning(false);
    }
  };

  const findings = scanReport?.findings || [];
  const filteredFindings = findings.filter((f) => {
    if (filterTab === 'All') return true;
    if (filterTab === 'Passed') return f.status === 'Passed';
    if (filterTab === 'Needs Review') return f.status === 'Needs Review';
    if (filterTab === 'Warning') return f.status === 'Warning';
    if (filterTab === 'Unable to Verify') return f.status === 'Unable to Verify';
    return true;
  });

  const score = scanReport?.scoreBreakdown?.score ?? null;
  const scoreLabel = scanReport?.scoreBreakdown?.label ?? 'Ungraded';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 py-8 px-4 sm:px-6 lg:px-8 selection:bg-cyan-500/30 selection:text-cyan-200">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Navigation Bar */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <button
            onClick={() => navigate('/dashboard')}
            className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors font-medium text-sm group"
          >
            <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
            Back to Dashboard
          </button>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 text-xs text-slate-400">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            Remote Configuration Scanner
          </div>
        </div>

        {/* Hero Header */}
        <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/95 to-slate-950 border border-slate-800 p-8 sm:p-10 shadow-2xl">
          <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-blue-600/10 via-cyan-500/10 to-transparent rounded-full blur-3xl pointer-events-none"></div>

          <div className="relative z-10 max-w-3xl space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold tracking-wide">
              <Globe className="w-3.5 h-3.5" />
              Service #8 · Website Security Scanner
            </div>

            <h1 className="text-3xl sm:text-4xl font-black tracking-tight text-white flex items-center gap-3">
              Website Security Scanner
            </h1>

            <p className="text-slate-400 text-base sm:text-lg leading-relaxed">
              Assess essential website security configurations, identify common weaknesses, and discover practical ways to improve your website's security.
            </p>
          </div>
        </div>

        {/* URL Input & Scanner Panel */}
        <div className="rounded-3xl bg-slate-900/70 border border-slate-800 p-6 sm:p-8 backdrop-blur-xl shadow-xl space-y-5">
          <form onSubmit={handleScanSubmit} className="space-y-4">
            <label className="block text-sm font-semibold text-slate-300">
              Target Website Address
            </label>

            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Globe className="w-5 h-5 absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  disabled={isScanning}
                  className="w-full bg-slate-950/80 border border-slate-700/80 rounded-2xl py-3.5 pl-12 pr-4 text-sm sm:text-base text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition-all font-mono disabled:opacity-50"
                />
              </div>

              <button
                type="submit"
                disabled={isScanning || !targetUrl.trim()}
                className="inline-flex items-center justify-center gap-2.5 px-8 py-3.5 rounded-2xl bg-gradient-to-r from-blue-600 via-cyan-500 to-cyan-400 text-slate-950 font-bold text-sm tracking-wide shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 hover:scale-[1.01] active:scale-[0.99] transition-all disabled:opacity-50 disabled:pointer-events-none"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                    Scanning Target...
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    Assess Website Security
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Authorization Reminder Notice */}
          <div className="flex items-start gap-3 p-4 rounded-2xl bg-slate-950/60 border border-slate-800/80 text-slate-400 text-xs sm:text-sm">
            <Info className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-semibold text-slate-300">Notice:</span> Only scan websites you own or have permission to assess. This tool performs basic configuration checks and is not a comprehensive security audit.
            </div>
          </div>

          {/* Error Message */}
          {errorMessage && (
            <motion.div
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-center gap-3"
            >
              <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </motion.div>
          )}

          {/* Live Scanning Indicator */}
          {isScanning && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8 rounded-2xl bg-slate-950/80 border border-cyan-500/30 text-center space-y-4"
            >
              <div className="relative w-16 h-16 mx-auto">
                <div className="absolute inset-0 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin"></div>
                <Globe className="w-8 h-8 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
              </div>
              <div className="space-y-1">
                <h4 className="font-bold text-white text-base">Conducting Genuine Security Checks</h4>
                <p className="text-xs text-slate-400">
                  Verifying TLS handshake, testing port 80 redirects, analyzing HTTP security headers, and inspecting SSL certificates...
                </p>
              </div>
            </motion.div>
          )}
        </div>

        {/* Scan Results Dashboard */}
        {scanReport && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            {/* Executive Summary & Score Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Executive Summary Card */}
              <div className="lg:col-span-2 rounded-3xl bg-slate-900/80 border border-slate-800 p-6 sm:p-7 backdrop-blur-xl shadow-xl flex flex-col justify-between space-y-6">
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 text-cyan-400" />
                      Executive Summary
                    </span>
                    <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                      Scan Completed
                    </span>
                  </div>

                  <h3 className="text-2xl font-black text-white break-all flex items-center gap-2">
                    {scanReport.target?.hostname}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    Validated IP: {scanReport.target?.primaryIp} · Tested: {new Date(scanReport.scanTimestamp).toUTCString()}
                  </p>
                </div>

                {/* Metrics Breakdown */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-slate-800">
                  <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
                    <div className="text-xs text-slate-400">Completed Checks</div>
                    <div className="text-xl font-bold text-white mt-1">
                      {scanReport.summary?.completedChecks}
                    </div>
                  </div>
                  <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
                    <div className="text-xs text-slate-400">Total Findings</div>
                    <div className="text-xl font-bold text-cyan-400 mt-1">
                      {scanReport.summary?.totalFindings}
                    </div>
                  </div>
                  <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
                    <div className="text-xs text-slate-400">Passed Checks</div>
                    <div className="text-xl font-bold text-emerald-400 mt-1">
                      {scanReport.summary?.passedCount}
                    </div>
                  </div>
                  <div className="p-3 rounded-2xl bg-slate-950/60 border border-slate-800">
                    <div className="text-xs text-slate-400">Issues / Reviews</div>
                    <div className="text-xl font-bold text-amber-400 mt-1">
                      {(scanReport.summary?.reviewCount || 0) + (scanReport.summary?.warningCount || 0)}
                    </div>
                  </div>
                </div>
              </div>

              {/* Security Score Gauge Card */}
              <div className="rounded-3xl bg-slate-900/80 border border-slate-800 p-6 sm:p-7 backdrop-blur-xl shadow-xl flex flex-col justify-between text-center space-y-4">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Configuration Score
                </span>

                <div className="relative w-36 h-36 mx-auto flex items-center justify-center">
                  {/* Circular Score Display */}
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      className="stroke-slate-800"
                      strokeWidth="8"
                      fill="transparent"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      className={`transition-all duration-1000 ${
                        score >= 80
                          ? 'stroke-emerald-400'
                          : score >= 60
                          ? 'stroke-cyan-400'
                          : score >= 40
                          ? 'stroke-amber-400'
                          : 'stroke-rose-500'
                      }`}
                      strokeWidth="8"
                      strokeDasharray={251.2}
                      strokeDashoffset={251.2 - (251.2 * (score || 0)) / 100}
                      strokeLinecap="round"
                      fill="transparent"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-black text-white">{score ?? 'N/A'}</span>
                    <span className="text-xs font-semibold text-slate-400">{scoreLabel}</span>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 leading-tight">
                  <span className="font-semibold text-slate-300 block mb-1">
                    Basic Configuration Score
                  </span>
                  Not a Measure of Overall Website Security.
                </div>
              </div>
            </div>

            {/* Security Overview Cards (4 Pillars) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
              {/* HTTPS Security */}
              {(() => {
                const card = scanReport.overviewCards?.httpsSecurity || {};
                const badge = STATUS_BADGE[card.status] || STATUS_BADGE.gray;
                const IconComponent = badge.icon;
                return (
                  <div className="rounded-3xl bg-slate-900/70 border border-slate-800 p-6 flex flex-col justify-between space-y-4 shadow-lg">
                    <div className="flex items-center justify-between">
                      <Lock className="w-6 h-6 text-cyan-400" />
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${badge.bg} ${badge.border} ${badge.text}`}>
                        {badge.label}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-lg font-bold text-white">{card.title}</h4>
                      <p className="text-xs text-slate-400 mt-1">{card.subtitle}</p>
                    </div>
                  </div>
                );
              })()}

              {/* TLS Certificate Status */}
              {(() => {
                const card = scanReport.overviewCards?.tlsCertificate || {};
                const badge = STATUS_BADGE[card.status] || STATUS_BADGE.gray;
                return (
                  <div className="rounded-3xl bg-slate-900/70 border border-slate-800 p-6 flex flex-col justify-between space-y-4 shadow-lg">
                    <div className="flex items-center justify-between">
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${badge.bg} ${badge.border} ${badge.text}`}>
                        {badge.label}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-lg font-bold text-white">{card.title}</h4>
                      <p className="text-xs text-slate-400 mt-1">{card.subtitle}</p>
                    </div>
                    {scanReport.tlsDetails?.available && (
                      <button
                        onClick={() => setShowTlsModal(true)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1 mt-2 text-left"
                      >
                        View Certificate Details <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                );
              })()}

              {/* Security Headers */}
              {(() => {
                const card = scanReport.overviewCards?.securityHeaders || {};
                const badge = STATUS_BADGE[card.status] || STATUS_BADGE.gray;
                return (
                  <div className="rounded-3xl bg-slate-900/70 border border-slate-800 p-6 flex flex-col justify-between space-y-4 shadow-lg">
                    <div className="flex items-center justify-between">
                      <Layers className="w-6 h-6 text-blue-400" />
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${badge.bg} ${badge.border} ${badge.text}`}>
                        {badge.label}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-lg font-bold text-white">{card.title}</h4>
                      <p className="text-xs text-slate-400 mt-1">{card.subtitle}</p>
                    </div>
                  </div>
                );
              })()}

              {/* Basic Configuration */}
              {(() => {
                const card = scanReport.overviewCards?.configuration || {};
                const badge = STATUS_BADGE[card.status] || STATUS_BADGE.gray;
                return (
                  <div className="rounded-3xl bg-slate-900/70 border border-slate-800 p-6 flex flex-col justify-between space-y-4 shadow-lg">
                    <div className="flex items-center justify-between">
                      <Server className="w-6 h-6 text-violet-400" />
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${badge.bg} ${badge.border} ${badge.text}`}>
                        {badge.label}
                      </span>
                    </div>
                    <div>
                      <h4 className="text-lg font-bold text-white">{card.title}</h4>
                      <p className="text-xs text-slate-400 mt-1">{card.subtitle}</p>
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Detailed Findings Table / Cards with Filter Tabs */}
            <div className="rounded-3xl bg-slate-900/80 border border-slate-800 p-6 sm:p-8 backdrop-blur-xl shadow-xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <h3 className="text-xl font-bold text-white">Detailed Findings</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Individual security indicator checks observed on the remote endpoint.
                  </p>
                </div>

                {/* Filter Tabs */}
                <div className="flex flex-wrap gap-1.5 p-1 rounded-2xl bg-slate-950/80 border border-slate-800">
                  {['All', 'Passed', 'Needs Review', 'Warning', 'Unable to Verify'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setFilterTab(tab)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                        filterTab === tab
                          ? 'bg-blue-600 text-white shadow-md'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>
              </div>

              {/* Findings List */}
              <div className="space-y-3">
                {filteredFindings.length === 0 ? (
                  <div className="p-8 text-center text-slate-400 text-sm">
                    No findings matching the selected filter.
                  </div>
                ) : (
                  filteredFindings.map((finding, idx) => {
                    const isExpanded = expandedFinding === idx;
                    const statusTheme =
                      finding.status === 'Passed'
                        ? 'border-emerald-500/20 bg-emerald-500/5'
                        : finding.status === 'Warning'
                        ? 'border-rose-500/20 bg-rose-500/5'
                        : finding.status === 'Needs Review'
                        ? 'border-amber-500/20 bg-amber-500/5'
                        : 'border-slate-800 bg-slate-950/40';

                    return (
                      <div
                        key={idx}
                        className={`rounded-2xl border transition-all ${statusTheme} overflow-hidden`}
                      >
                        <div
                          onClick={() => setExpandedFinding(isExpanded ? null : idx)}
                          className="p-4 sm:p-5 flex items-center justify-between gap-4 cursor-pointer hover:bg-slate-800/30 transition-colors"
                        >
                          <div className="flex items-center gap-3.5 flex-1 min-w-0">
                            {finding.status === 'Passed' ? (
                              <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                            ) : finding.status === 'Warning' ? (
                              <XCircle className="w-5 h-5 text-rose-400 flex-shrink-0" />
                            ) : finding.status === 'Needs Review' ? (
                              <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />
                            ) : (
                              <HelpCircle className="w-5 h-5 text-slate-400 flex-shrink-0" />
                            )}

                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4 className="font-bold text-white text-sm sm:text-base">
                                  {finding.checkName}
                                </h4>
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${SEVERITY_BADGE[finding.severity] || 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                                  {finding.severity}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400 truncate mt-0.5">
                                {finding.observedResult}
                              </p>
                            </div>
                          </div>

                          <div className="flex items-center gap-3 flex-shrink-0">
                            <span
                              className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                                finding.status === 'Passed'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                  : finding.status === 'Warning'
                                  ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                                  : finding.status === 'Needs Review'
                                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700'
                              }`}
                            >
                              {finding.status}
                            </span>
                            <ChevronDown
                              className={`w-4 h-4 text-slate-400 transition-transform ${
                                isExpanded ? 'rotate-180' : ''
                              }`}
                            />
                          </div>
                        </div>

                        {/* Expanded Finding Detail */}
                        <AnimatePresence>
                          {isExpanded && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              className="px-5 pb-5 pt-2 border-t border-slate-800/60 bg-slate-950/60 space-y-3 text-xs sm:text-sm"
                            >
                              <div>
                                <span className="font-semibold text-slate-300 block mb-1">
                                  Why It Matters:
                                </span>
                                <p className="text-slate-400 leading-relaxed">
                                  {finding.whyItMatters}
                                </p>
                              </div>

                              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                                <span className="font-semibold text-cyan-400 block mb-1">
                                  Recommended Remediation:
                                </span>
                                <p className="text-slate-300 leading-relaxed font-mono text-xs">
                                  {finding.recommendation}
                                </p>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Remediation Guidance Section */}
            {scanReport.remediationGuidance?.length > 0 && (
              <div className="rounded-3xl bg-slate-900/80 border border-slate-800 p-6 sm:p-8 backdrop-blur-xl shadow-xl space-y-5">
                <div className="flex items-center gap-3">
                  <Sparkles className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-xl font-bold text-white">Actionable Remediation Guidance</h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {scanReport.remediationGuidance.map((rec, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800/80 space-y-1.5"
                    >
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                        <h4 className="font-bold text-slate-200 text-sm">{rec.category}</h4>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {rec.action}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* TLS Certificate Details Drawer / Modal */}
        <AnimatePresence>
          {showTlsModal && scanReport?.tlsDetails && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                onClick={() => setShowTlsModal(false)}
                className="fixed inset-0 bg-black/70 backdrop-blur-sm"
              />

              <motion.div
                initial={{ scale: 0.95, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.95, opacity: 0 }}
                className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 shadow-2xl z-10 space-y-6 max-h-[90vh] overflow-y-auto"
              >
                <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                  <div className="flex items-center gap-2.5">
                    <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    <h3 className="text-xl font-bold text-white">TLS Certificate Details</h3>
                  </div>
                  <button
                    onClick={() => setShowTlsModal(false)}
                    className="p-2 text-slate-400 hover:text-white"
                  >
                    ✕
                  </button>
                </div>

                <div className="space-y-4 text-xs sm:text-sm">
                  <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Subject (Common Name):</span>
                      <span className="font-bold text-white font-mono">{scanReport.tlsDetails.subject?.commonName || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Issuer:</span>
                      <span className="font-semibold text-slate-200">{scanReport.tlsDetails.issuer?.organization || scanReport.tlsDetails.issuer?.commonName || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Protocol:</span>
                      <span className="font-mono text-cyan-400">{scanReport.tlsDetails.protocol || 'TLS'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Cipher Suite:</span>
                      <span className="font-mono text-slate-300">{scanReport.tlsDetails.cipher || 'N/A'}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800">
                      <div className="text-slate-400 text-xs mb-1">Valid From (UTC):</div>
                      <div className="font-mono text-slate-200 text-xs">{scanReport.tlsDetails.validFrom}</div>
                    </div>
                    <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800">
                      <div className="text-slate-400 text-xs mb-1">Expiration Date (UTC):</div>
                      <div className="font-mono text-slate-200 text-xs">{scanReport.tlsDetails.validTo}</div>
                      <div className="text-emerald-400 font-semibold text-xs mt-1">
                        {scanReport.tlsDetails.daysRemaining} days remaining
                      </div>
                    </div>
                  </div>

                  {scanReport.tlsDetails.subjectAltNames?.length > 0 && (
                    <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-2">
                      <span className="text-slate-400 text-xs block">Subject Alternative Names (SANs):</span>
                      <div className="flex flex-wrap gap-1.5">
                        {scanReport.tlsDetails.subjectAltNames.map((san, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400 text-xs font-mono"
                          >
                            {san}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {scanReport.tlsDetails.fingerprint && (
                    <div className="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400 text-xs">SHA-256 Fingerprint:</span>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(scanReport.tlsDetails.fingerprint);
                            setCopiedFingerprint(true);
                            setTimeout(() => setCopiedFingerprint(false), 2000);
                          }}
                          className="text-xs text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                        >
                          {copiedFingerprint ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          {copiedFingerprint ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <div className="font-mono text-slate-300 text-xs break-all">
                        {scanReport.tlsDetails.fingerprint}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default WebsiteSecurityScreen;
