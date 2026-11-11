import React, { useState, useEffect, useRef } from "react";
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  Wifi,
  Monitor,
  Globe,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Lock,
  Unlock,
  Fingerprint,
  Cpu,
  Clock,
  Network,
  Eye,
  Zap,
  Info,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { RadialBarChart, RadialBar, PolarAngleAxis } from "recharts";
import { collectTelemetry } from "../utils/browserAudit";
import api from "../utils/api";

// ─── Scanning Steps Config ─────────────────────────────────────────────────────
const SCAN_STEPS = [
  { id: 1, label: "Initializing Browser Sandbox Analysis...", icon: Monitor, duration: 800  },
  { id: 2, label: "Extracting OS & Browser Fingerprint...",   icon: Fingerprint, duration: 900 },
  { id: 3, label: "Probing WebRTC STUN Channels...",         icon: Wifi, duration: 1200 },
  { id: 4, label: "Collecting Fingerprint Vectors...",       icon: Cpu, duration: 700  },
  { id: 5, label: "Resolving Public IP Address...",          icon: Globe, duration: 600  },
  { id: 6, label: "Probing Public Firewall Ports...",        icon: Network, duration: 1800 },
  { id: 7, label: "Running Threat Analysis Engine...",       icon: Zap, duration: 700  },
  { id: 8, label: "Generating Security Report...",           icon: ShieldCheck, duration: 500  },
];

// ─── Severity Config ───────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  critical: {
    bg: "bg-red-950/60",
    border: "border-red-500/60",
    badge: "bg-red-500 text-white",
    text: "text-red-400",
    icon: ShieldAlert,
  },
  high: {
    bg: "bg-orange-950/60",
    border: "border-orange-500/50",
    badge: "bg-orange-500 text-white",
    text: "text-orange-400",
    icon: AlertTriangle,
  },
  medium: {
    bg: "bg-yellow-950/40",
    border: "border-yellow-500/40",
    badge: "bg-yellow-500 text-black",
    text: "text-yellow-400",
    icon: Eye,
  },
  low: {
    bg: "bg-emerald-950/40",
    border: "border-emerald-500/40",
    badge: "bg-emerald-500 text-white",
    text: "text-emerald-400",
    icon: CheckCircle,
  },
};

const PORT_RISK_COLORS = {
  "Open/Vulnerable": { bg: "bg-red-900/60", border: "border-red-500/60", dot: "bg-red-500", text: "text-red-400" },
  "Filtered/Secure": { bg: "bg-emerald-900/30", border: "border-emerald-500/30", dot: "bg-emerald-500", text: "text-emerald-400" },
  "Error":           { bg: "bg-slate-800/60",   border: "border-slate-600/40",   dot: "bg-slate-500",   text: "text-slate-400" },
};

// ─── Score Gauge Component ─────────────────────────────────────────────────────
function ScoreGauge({ score }) {
  const color =
    score >= 80 ? "#10b981" :
    score >= 60 ? "#f59e0b" :
    score >= 40 ? "#f97316" :
                  "#ef4444";

  const label =
    score >= 80 ? "Good"     :
    score >= 60 ? "Fair"     :
    score >= 40 ? "Poor"     :
                  "Critical";

  const data = [{ value: score, fill: color }];

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative">
        <RadialBarChart
          width={200}
          height={200}
          cx="50%"
          cy="50%"
          innerRadius="68%"
          outerRadius="92%"
          data={data}
          startAngle={90}
          endAngle={-270}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar
            background={{ fill: "#1e293b" }}
            dataKey="value"
            cornerRadius={12}
            isAnimationActive={true}
            animationBegin={200}
            animationDuration={1200}
          />
        </RadialBarChart>
        <div
          className="absolute inset-0 flex flex-col items-center justify-center"
          style={{ pointerEvents: "none" }}
        >
          <span className="text-4xl font-black" style={{ color }}>{score}</span>
          <span className="text-xs font-bold text-slate-400 uppercase tracking-widest mt-0.5">/100</span>
          <span className="text-sm font-bold mt-1" style={{ color }}>{label}</span>
        </div>
      </div>
      <p className="text-xs text-slate-500 text-center">Overall Security Score</p>
    </div>
  );
}

// ─── Scanning Matrix Screen ────────────────────────────────────────────────────
function ScanningScreen({ currentStep }) {
  const steps = SCAN_STEPS;
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] py-16 px-4">
      {/* Animated pulse ring */}
      <div className="relative mb-10">
        <div className="w-24 h-24 rounded-full bg-cyan-500/10 border-2 border-cyan-500/30 flex items-center justify-center animate-pulse">
          <div className="w-16 h-16 rounded-full bg-cyan-500/20 border-2 border-cyan-500/50 flex items-center justify-center">
            <ShieldAlert className="w-8 h-8 text-cyan-400 animate-bounce" />
          </div>
        </div>
        {[0,1,2].map(i => (
          <div
            key={i}
            className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping"
            style={{ animationDelay: `${i * 0.4}s`, animationDuration: "1.6s" }}
          />
        ))}
      </div>

      <h2 className="text-xl font-bold text-white mb-1">Scanning Your Environment</h2>
      <p className="text-slate-400 text-sm mb-10">Do not close this window...</p>

      <div className="w-full max-w-md space-y-2.5">
        {steps.map((step, i) => {
          const Icon = step.icon;
          const isDone = i < currentStep;
          const isActive = i === currentStep;
          return (
            <div
              key={step.id}
              className={`flex items-center gap-3 px-4 py-2.5 rounded-xl border transition-all duration-300 ${
                isActive
                  ? "border-cyan-500/60 bg-cyan-950/50 shadow-lg shadow-cyan-500/10"
                  : isDone
                  ? "border-emerald-500/30 bg-emerald-950/20"
                  : "border-slate-700/40 bg-slate-800/20 opacity-40"
              }`}
            >
              <Icon className={`w-4 h-4 flex-shrink-0 ${
                isActive ? "text-cyan-400 animate-pulse" : isDone ? "text-emerald-400" : "text-slate-600"
              }`} />
              <span className={`text-sm font-mono flex-1 ${
                isActive ? "text-cyan-300" : isDone ? "text-emerald-400" : "text-slate-600"
              }`}>
                {step.label}
              </span>
              {isDone && <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />}
              {isActive && (
                <span className="flex gap-0.5">
                  {[0,1,2].map(d => (
                    <span key={d} className="w-1 h-1 rounded-full bg-cyan-400 animate-bounce"
                      style={{ animationDelay: `${d * 0.15}s` }} />
                  ))}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Pre-Scan State ────────────────────────────────────────────────────────────
function PreScanScreen({ onScan, isLoading }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[65vh] text-center px-4 py-16">
      {/* Hero Shield */}
      <div className="relative mb-10">
        <div className="w-32 h-32 rounded-3xl bg-gradient-to-br from-cyan-500/20 to-violet-600/20 border border-cyan-500/30 flex items-center justify-center shadow-2xl shadow-cyan-500/10">
          <ShieldCheck className="w-16 h-16 text-cyan-400" strokeWidth={1.5} />
        </div>
        <div className="absolute -inset-2 rounded-3xl bg-gradient-to-br from-cyan-500/5 to-violet-600/5 blur-xl -z-10" />
      </div>

      <h2 className="text-3xl font-black text-white mb-3 leading-tight">
        Client Environment<br />
        <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-violet-400">
          & Network Audit
        </span>
      </h2>
      <p className="text-slate-400 max-w-md mb-10 leading-relaxed">
        This tool analyzes your browser, OS, and network for real-world vulnerabilities,
        privacy leaks, and exposed firewall ports.
      </p>

      {/* Feature pills */}
      <div className="flex flex-wrap justify-center gap-2 mb-10">
        {[
          { icon: Monitor, label: "Browser & OS Analysis" },
          { icon: Wifi, label: "WebRTC Leak Detection" },
          { icon: Fingerprint, label: "Fingerprint Profiling" },
          { icon: Network, label: "Public Port Scan" },
        ].map(({ icon: Icon, label }) => (
          <div key={label} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-800/70 border border-slate-700/50 text-slate-300 text-xs font-medium">
            <Icon className="w-3.5 h-3.5 text-cyan-400" />
            {label}
          </div>
        ))}
      </div>

      {/* Disclaimer */}
      <div className="flex items-start gap-3 px-5 py-4 rounded-xl bg-amber-950/40 border border-amber-500/30 text-left max-w-md mb-10">
        <Info className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-amber-300 font-semibold text-sm">Disclaimer</p>
          <p className="text-amber-400/80 text-xs leading-relaxed mt-0.5">
            This audit will perform a non-intrusive external port scan on your network's
            public IP address using your server as the scanning origin. No data is stored.
            Only standard TCP connection attempts are made with a strict 1.5s timeout.
          </p>
        </div>
      </div>

      <button
        id="start-audit-btn"
        onClick={onScan}
        disabled={isLoading}
        className="group relative px-10 py-4 rounded-2xl font-bold text-lg text-white shadow-2xl
          bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500
          transition-all duration-300 hover:scale-105 hover:shadow-cyan-500/30 active:scale-95
          disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:scale-100"
      >
        <span className="flex items-center gap-3">
          <ShieldAlert className="w-6 h-6" />
          Audit My Connection & Browser
        </span>
        <div className="absolute inset-0 rounded-2xl bg-white/10 opacity-0 group-hover:opacity-100 transition-opacity" />
      </button>
    </div>
  );
}

// ─── Main Screen ───────────────────────────────────────────────────────────────
const ClientAuditScreen = () => {
  const navigate = useNavigate();
  const [scanState, setScanState] = useState("idle"); // idle | scanning | results | error
  const [currentScanStep, setCurrentScanStep] = useState(0);
  const [report, setReport] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const stepIntervalRef = useRef(null);

  // Animate steps while scanning
  useEffect(() => {
    if (scanState === "scanning") {
      setCurrentScanStep(0);
      let step = 0;
      const advance = () => {
        step++;
        if (step < SCAN_STEPS.length) {
          setCurrentScanStep(step);
          const delay = SCAN_STEPS[step]?.duration ?? 800;
          stepIntervalRef.current = setTimeout(advance, delay);
        }
      };
      stepIntervalRef.current = setTimeout(advance, SCAN_STEPS[0].duration);
    }
    return () => clearTimeout(stepIntervalRef.current);
  }, [scanState]);

  const handleStartScan = async () => {
    setScanState("scanning");
    setErrorMsg("");
    const scanStartTime = Date.now();

    try {
      // Step 1: Collect all browser telemetry client-side
      const telemetry = await collectTelemetry();

      // Step 2: POST to backend (runs port scan + threat analysis)
      // Override timeout: port scanner can take up to 15s (10 ports × 1500ms timeout)
      // plus ~5s for ipify.org fallback IP resolution = need at least 25s.
      const { data } = await api.post("/audits/client", { telemetry }, { timeout: 35000 });

      // Wait for animation to finish before showing results (looks better UX-wise)
      const totalAnimDuration = SCAN_STEPS.reduce((s, st) => s + st.duration, 0);
      const elapsed = Date.now() - scanStartTime;
      const remaining = Math.max(0, totalAnimDuration - elapsed);
      if (remaining > 0) await new Promise(r => setTimeout(r, remaining));

      setReport(data);
      setScanState("results");
    } catch (err) {
      console.error("Audit failed:", err);
      setErrorMsg(err?.response?.data?.error || "The audit could not be completed. Please try again.");
      setScanState("error");
    }
  };

  const handleReset = () => {
    setReport(null);
    setScanState("idle");
    setCurrentScanStep(0);
  };

  // ── Results Render ────────────────────────────────────────────────────────────
  const renderResults = () => {
    if (!report) return null;
    const { telemetry, portScan, securityScore, recommendations, summary, publicIp, timestamp } = report;

    return (
      <div className="space-y-8 animate-fade-in">

        {/* Summary Banner */}
        <div className={`rounded-2xl p-5 border flex flex-wrap items-center gap-4 ${
          summary.overallRisk === "Critical" ? "bg-red-950/50 border-red-500/40" :
          summary.overallRisk === "High"     ? "bg-orange-950/50 border-orange-500/40" :
          summary.overallRisk === "Medium"   ? "bg-yellow-950/40 border-yellow-500/30" :
                                              "bg-emerald-950/30 border-emerald-500/30"
        }`}>
          <div className="flex items-center gap-3 flex-1 min-w-0">
            {summary.overallRisk === "Critical" || summary.overallRisk === "High"
              ? <ShieldAlert className="w-6 h-6 text-red-400 flex-shrink-0" />
              : <ShieldCheck className="w-6 h-6 text-emerald-400 flex-shrink-0" />
            }
            <div className="min-w-0">
              <p className="font-bold text-white text-sm">
                Audit Complete — Risk Level:&nbsp;
                <span className={
                  summary.overallRisk === "Critical" ? "text-red-400" :
                  summary.overallRisk === "High"     ? "text-orange-400" :
                  summary.overallRisk === "Medium"   ? "text-yellow-400" :
                                                      "text-emerald-400"
                }>{summary.overallRisk}</span>
              </p>
              <p className="text-slate-400 text-xs mt-0.5 font-mono truncate">
                {publicIp} &nbsp;·&nbsp; {new Date(timestamp).toLocaleString()}
              </p>
            </div>
          </div>
          <button
            onClick={handleReset}
            className="btn btn-sm btn-outline border-slate-600 text-slate-300 hover:bg-slate-700 shrink-0"
          >
            Re-Scan
          </button>
        </div>

        {/* Top Grid: Score + Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Score */}
          <div className="bg-slate-900/80 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/50 shadow-xl flex flex-col items-center justify-center">
            <ScoreGauge score={securityScore} />
          </div>

          {/* Summary Stats */}
          <div className="md:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Open Ports", value: summary.openPorts,      color: summary.openPorts > 0 ? "text-red-400" : "text-emerald-400",    icon: Unlock },
              { label: "Filtered Ports", value: summary.filteredPorts, color: "text-emerald-400",                                           icon: Lock },
              { label: "Privacy Leaks", value: summary.privacyLeaks, color: summary.privacyLeaks > 0 ? "text-yellow-400" : "text-emerald-400", icon: Eye },
              { label: "Recommendations", value: recommendations.length, color: "text-cyan-400",                                            icon: ShieldCheck },
            ].map(({ label, value, color, icon: Icon }) => (
              <div key={label} className="bg-slate-900/80 backdrop-blur-xl rounded-2xl p-4 border border-slate-700/50 shadow-xl flex flex-col items-center justify-center text-center gap-2">
                <Icon className={`w-6 h-6 ${color}`} />
                <span className={`text-3xl font-black ${color}`}>{value}</span>
                <span className="text-slate-500 text-xs font-medium">{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Section 1: Browser & Privacy ─────────────────────────────────── */}
        <div className="bg-slate-900/80 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/50 shadow-xl">
          <h3 className="text-lg font-bold text-white mb-5 flex items-center gap-2.5">
            <Monitor className="w-5 h-5 text-violet-400" />
            Browser & Privacy
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* OS */}
            <InfoCard label="Operating System" value={telemetry.os}
              icon={Monitor} status={telemetry.os.includes("(EOL)") ? "warn" : "ok"} />
            {/* Browser */}
            <InfoCard label="Browser" value={`${telemetry.browser} ${telemetry.browserVersion}`}
              icon={Globe} status={telemetry.isOutdated ? "bad" : "ok"}
              badge={telemetry.isOutdated ? "Outdated" : "Up to Date"}
              badgeColor={telemetry.isOutdated ? "badge-error" : "badge-success"} />
            {/* Protocol */}
            <InfoCard label="Connection Protocol" value={telemetry.protocol.replace(":", "").toUpperCase()}
              icon={telemetry.isHttps ? Lock : Unlock} status={telemetry.isHttps ? "ok" : "bad"}
              badge={telemetry.isHttps ? "Secure" : "Insecure"}
              badgeColor={telemetry.isHttps ? "badge-success" : "badge-error"} />
            {/* WebRTC */}
            <InfoCard label="WebRTC IP Leak" value={telemetry.webrtcLeakedIp ?? "No Leak Detected"}
              icon={Wifi} status={telemetry.webrtcLeakedIp ? "warn" : "ok"}
              badge={telemetry.webrtcLeakedIp ? "Leaked" : "Secure"}
              badgeColor={telemetry.webrtcLeakedIp ? "badge-warning" : "badge-success"} />
            {/* Screen */}
            <InfoCard label="Screen Resolution" value={telemetry.screenResolution} icon={Monitor} status="info" />
            {/* Timezone */}
            <InfoCard label="Timezone" value={telemetry.timezone} icon={Clock} status="info" />
            {/* WebGL */}
            <InfoCard label="WebGL Renderer" value={telemetry.webglRenderer} icon={Cpu} status="info"
              className="sm:col-span-2 lg:col-span-2" />
            {/* Fingerprint Score */}
            <div className={`rounded-xl p-4 border ${
              telemetry.fingerprintScore >= 75
                ? "bg-yellow-950/40 border-yellow-500/30"
                : "bg-emerald-950/30 border-emerald-500/30"
            }`}>
              <div className="flex items-center gap-2 mb-2">
                <Fingerprint className={`w-4 h-4 ${telemetry.fingerprintScore >= 75 ? "text-yellow-400" : "text-emerald-400"}`} />
                <span className="text-slate-400 text-xs font-medium">Fingerprint Trackability</span>
              </div>
              <div className="flex items-end gap-2">
                <span className={`text-2xl font-black ${telemetry.fingerprintScore >= 75 ? "text-yellow-400" : "text-emerald-400"}`}>
                  {telemetry.fingerprintScore}
                </span>
                <span className="text-slate-500 text-sm mb-0.5">/ 100</span>
              </div>
              <div className="mt-2 h-1.5 rounded-full bg-slate-700">
                <div
                  className={`h-full rounded-full transition-all duration-1000 ${
                    telemetry.fingerprintScore >= 75 ? "bg-yellow-400" : "bg-emerald-400"
                  }`}
                  style={{ width: `${telemetry.fingerprintScore}%` }}
                />
              </div>
              <p className="text-xs text-slate-500 mt-1.5">
                {telemetry.fingerprintScore >= 75 ? "High — easily trackable" : "Low — good privacy"}
              </p>
            </div>
          </div>
        </div>

        {/* ── Section 2: Network & Firewall ────────────────────────────────── */}
        <div className="bg-slate-900/80 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/50 shadow-xl">
          <h3 className="text-lg font-bold text-white mb-1 flex items-center gap-2.5">
            <Network className="w-5 h-5 text-cyan-400" />
            Network & Firewall
          </h3>
          <p className="text-slate-500 text-xs mb-5">
            Scanned from server against your public IP:&nbsp;
            <code className="text-cyan-400 font-mono bg-slate-800 px-1.5 py-0.5 rounded">{publicIp}</code>
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
            {portScan.map((port) => {
              const cfg = PORT_RISK_COLORS[port.status];
              return (
                <div key={port.port}
                  className={`rounded-xl p-3.5 border ${cfg.bg} ${cfg.border} flex flex-col gap-1.5`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-xs font-mono font-bold">:{port.port}</span>
                    <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
                  </div>
                  <p className="text-white text-sm font-semibold leading-tight">{port.service}</p>
                  <p className={`text-xs font-bold ${cfg.text}`}>{port.status}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Section 3: Recommendations ───────────────────────────────────── */}
        <div className="bg-slate-900/80 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/50 shadow-xl">
          <h3 className="text-lg font-bold text-white mb-5 flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            Actionable Recommendations
            <span className="ml-auto text-xs font-medium bg-slate-800 text-slate-400 px-2 py-1 rounded-lg">
              {recommendations.length} findings
            </span>
          </h3>

          <div className="space-y-3">
            {recommendations.map((rec) => {
              const cfg = SEVERITY_CONFIG[rec.severity];
              const Icon = cfg.icon;
              return (
                <div key={rec.id}
                  className={`rounded-xl p-4 border ${cfg.bg} ${cfg.border} flex gap-3.5`}
                >
                  <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${cfg.text}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <p className="font-bold text-white text-sm">{rec.title}</p>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full uppercase ${cfg.badge}`}>
                        {rec.severity}
                      </span>
                    </div>
                    <p className="text-slate-400 text-xs leading-relaxed">{rec.description}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-950 p-4 md:p-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <button
          onClick={() => navigate("/dashboard")}
          className="p-2 bg-slate-900 border border-slate-800 rounded-xl hover:bg-slate-800 transition-colors"
        >
          <ArrowLeft className="w-5 h-5 text-slate-400" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-cyan-400" />
            Security Audits
          </h1>
          <p className="text-slate-500 text-sm">Client Environment & Network Audit</p>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-6xl mx-auto">
        {scanState === "idle"     && <PreScanScreen onScan={handleStartScan} />}
        {scanState === "scanning" && <ScanningScreen currentStep={currentScanStep} />}
        {scanState === "results"  && renderResults()}
        {scanState === "error"    && (
          <div className="flex flex-col items-center justify-center min-h-[50vh] text-center gap-6">
            <div className="w-20 h-20 rounded-2xl bg-red-950/60 border border-red-500/40 flex items-center justify-center">
              <XCircle className="w-10 h-10 text-red-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white mb-2">Audit Failed</h2>
              <p className="text-slate-400 text-sm max-w-sm">{errorMsg}</p>
            </div>
            <button
              onClick={handleReset}
              className="btn btn-outline border-slate-600 text-slate-300 hover:bg-slate-800"
            >
              Try Again
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// ─── Helper: Info Card ─────────────────────────────────────────────────────────
function InfoCard({ label, value, icon: Icon, status, badge, badgeColor, className = "" }) {
  const borderColor =
    status === "bad"  ? "border-red-500/40 bg-red-950/30" :
    status === "warn" ? "border-yellow-500/30 bg-yellow-950/20" :
    status === "ok"   ? "border-emerald-500/30 bg-emerald-950/20" :
                        "border-slate-700/50 bg-slate-800/40";

  return (
    <div className={`rounded-xl p-4 border ${borderColor} ${className}`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`w-4 h-4 flex-shrink-0 ${
          status === "bad" ? "text-red-400" : status === "warn" ? "text-yellow-400" : status === "ok" ? "text-emerald-400" : "text-slate-400"
        }`} />
        <span className="text-slate-400 text-xs font-medium truncate">{label}</span>
      </div>
      <p className="text-white text-sm font-semibold leading-tight break-all">{value}</p>
      {badge && (
        <span className={`badge badge-sm mt-2 ${badgeColor}`}>{badge}</span>
      )}
    </div>
  );
}

export default ClientAuditScreen;
