import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  KeyRound,
  Shield,
  ShieldCheck,
  Lock,
  Copy,
  Check,
  RefreshCw,
  Eye,
  EyeOff,
  X,
  ArrowLeft,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Cpu,
  Sparkles,
  Sliders,
  HelpCircle,
  BookOpen,
  CheckSquare,
  Square,
  Zap,
  Fingerprint,
  ChevronDown,
  Layers,
  Terminal,
} from 'lucide-react';
import { analyzePassword } from '../utils/passwordAnalyzer';
import {
  generateSecurePassword,
  generateSecurePassphrase,
} from '../utils/passwordGenerator';

// ── Color and Theme Palettes ──────────────────────────────────────────────────
const STRENGTH_THEMES = {
  empty: {
    bg: 'bg-slate-500/10',
    border: 'border-slate-800',
    text: 'text-slate-400',
    bar: 'bg-slate-700',
    ring: 'stroke-slate-700',
    glow: 'shadow-transparent',
    badge: 'bg-slate-800 text-slate-300 border-slate-700',
  },
  very_weak: {
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/30',
    text: 'text-rose-400',
    bar: 'bg-rose-500',
    ring: 'stroke-rose-500',
    glow: 'shadow-rose-500/20',
    badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  },
  weak: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    bar: 'bg-orange-500',
    ring: 'stroke-orange-500',
    glow: 'shadow-orange-500/20',
    badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  },
  moderate: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    bar: 'bg-amber-500',
    ring: 'stroke-amber-500',
    glow: 'shadow-amber-500/20',
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  },
  strong: {
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-400',
    bar: 'bg-cyan-500',
    ring: 'stroke-cyan-500',
    glow: 'shadow-cyan-500/20',
    badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  },
  very_strong: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    bar: 'bg-emerald-500',
    ring: 'stroke-emerald-500',
    glow: 'shadow-emerald-500/20',
    badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  },
};

// ── Educational Myths vs Facts Data ───────────────────────────────────────────
const MYTHS_AND_FACTS = [
  {
    id: 'm1',
    myth: 'Adding @123 or changing "E" to "3" makes my password unbreakable.',
    fact: 'Modern dictionary attack rules (like Hashcat masks) automatically generate and test common leet-speak patterns in milliseconds. Predictable substitutions provide almost zero real entropy.',
    takeaway: 'Use genuinely unpredictable characters or a multi-word passphrase rather than basic letter substitutions.',
  },
  {
    id: 'm2',
    myth: 'A short, complex password (e.g. 8 chars with symbols) is stronger than a long passphrase.',
    fact: 'Length scales entropy exponentially. A 16-character passphrase like "crimson-falcon-beacon" has vastly more possible combinations than an 8-character "P@$$w0rd", making it far harder to crack.',
    takeaway: 'Length always trumps complexity. Prefer 14-20 characters whenever possible.',
  },
  {
    id: 'm3',
    myth: 'You must change your password every 30 to 60 days.',
    fact: 'NIST (National Institute of Standards & Technology) specifically discourages arbitrary mandatory password rotations. Frequent resets lead users to make minor predictable variations (e.g., Spring24! to Summer24!).',
    takeaway: 'Only change passwords when there is evidence of a security breach or exposure.',
  },
  {
    id: 'm4',
    myth: 'Special characters alone guarantee a password cannot be cracked.',
    fact: 'If the overall structure follows standard human conventions (Capital letter + dictionary word + symbol + 2 numbers), attackers prioritize this exact syntax schema.',
    takeaway: 'True security comes from unpredictable randomness across the entire string.',
  },
];

// ── Educational Concept Cards ─────────────────────────────────────────────────
const CONCEPTS = [
  {
    icon: Lock,
    title: 'Length vs Complexity',
    desc: 'Each additional character multiplies the total combinations by the character pool size. Adding 4 characters increases crack time by billions of times.',
    tag: 'Exponential Entropy',
  },
  {
    icon: Cpu,
    title: 'Modern GPU Clusters',
    desc: 'Attack rigs using 8x RTX 4090 GPUs test over 200 billion NTLM/MD5 hashes per second. Short passwords (< 10 chars) are cracked in minutes.',
    tag: 'Brute-Force Realities',
  },
  {
    icon: Fingerprint,
    title: 'Credential Stuffing',
    desc: 'Over 80% of account takeovers happen because users reuse the exact same password across multiple sites when one service suffers a breach.',
    tag: 'Zero-Reuse Principle',
  },
  {
    icon: KeyRound,
    title: 'Password Managers',
    desc: 'Humans cannot safely memorize dozens of 20-character random strings. A verified manager (e.g. Bitwarden, 1Password) handles unique secrets seamlessly.',
    tag: 'Best Practice',
  },
  {
    icon: ShieldCheck,
    title: 'Multi-Factor Auth (MFA)',
    desc: 'Even if your password is stolen or keylogged, an authenticator app (TOTP) or hardware security key (FIDO2/WebAuthn) prevents unauthorized logins.',
    tag: 'Defense in Depth',
  },
  {
    icon: Terminal,
    title: 'Passphrase Diceware',
    desc: 'Combining 4-5 unrelated random words creates 65+ bits of entropy that is mathematically resistant to GPU clusters while remaining easy for humans to type.',
    tag: 'Usable Security',
  },
];

const PasswordSecurityScreen = () => {
  const navigate = useNavigate();

  // Active view tab: 'analyzer' | 'generator' | 'passphrase' | 'checklist' | 'education'
  const [activeTab, setActiveTab] = useState('analyzer');

  // Input state (Kept strictly local; cleared on unmount/clear)
  const [passwordInput, setPasswordInput] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [copiedToast, setCopiedToast] = useState(false);
  const [expandedMyth, setExpandedMyth] = useState(null);

  // Manual Checklist state (User interactive toggles)
  const [checklistState, setChecklistState] = useState({
    uniquePerAccount: true,
    usesPasswordManager: false,
    mfaEnabled: true,
    noPersonalInfo: true,
  });

  // Password Generator settings
  const [genLength, setGenLength] = useState(18);
  const [genUpper, setGenUpper] = useState(true);
  const [genLower, setGenLower] = useState(true);
  const [genNumbers, setGenNumbers] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);
  const [genNoAmbiguous, setGenNoAmbiguous] = useState(true);
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [genCopied, setGenCopied] = useState(false);

  // Passphrase Generator settings
  const [passWordCount, setPassWordCount] = useState(4);
  const [passSeparator, setPassSeparator] = useState('-');
  const [passCapitalize, setPassCapitalize] = useState('title');
  const [passIncludeSuffix, setPassIncludeSuffix] = useState(true);
  const [passSuffixType, setPassSuffixType] = useState('number');
  const [generatedPassphrase, setGeneratedPassphrase] = useState('');
  const [passCopied, setPassCopied] = useState(false);

  // Run initial random generation once on mount
  useEffect(() => {
    handleGeneratePassword();
    handleGeneratePassphrase();
    // Safety cleanup: purge state on unmount
    return () => {
      setPasswordInput('');
      setGeneratedPassword('');
      setGeneratedPassphrase('');
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Compute live password analysis (100% Client-Side)
  const analysis = useMemo(() => {
    return analyzePassword(passwordInput);
  }, [passwordInput]);

  const theme = STRENGTH_THEMES[analysis.themeKey] || STRENGTH_THEMES.empty;

  // Analysis of the generated password
  const genAnalysis = useMemo(() => {
    return analyzePassword(generatedPassword);
  }, [generatedPassword]);

  // Analysis of the generated passphrase
  const passAnalysis = useMemo(() => {
    return analyzePassword(generatedPassphrase);
  }, [generatedPassphrase]);

  // Handlers for generation
  const handleGeneratePassword = useCallback(() => {
    const pwd = generateSecurePassword({
      length: genLength,
      includeUppercase: genUpper,
      includeLowercase: genLower,
      includeNumbers: genNumbers,
      includeSymbols: genSymbols,
      excludeAmbiguous: genNoAmbiguous,
    });
    setGeneratedPassword(pwd);
  }, [genLength, genUpper, genLower, genNumbers, genSymbols, genNoAmbiguous]);

  const handleGeneratePassphrase = useCallback(() => {
    const phrase = generateSecurePassphrase({
      wordCount: passWordCount,
      separator: passSeparator,
      capitalize: passCapitalize,
      includeSuffix: passIncludeSuffix,
      suffixType: passSuffixType,
    });
    setGeneratedPassphrase(phrase);
  }, [passWordCount, passSeparator, passCapitalize, passIncludeSuffix, passSuffixType]);

  // Copy helper with fallback
  const copyToClipboard = async (text, setCopiedFn) => {
    if (!text) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        textArea.remove();
      }
      setCopiedFn(true);
      setTimeout(() => setCopiedFn(false), 2200);
    } catch (err) {
      console.warn('Clipboard copy permission failed:', err);
    }
  };

  const handleTestInAnalyzer = (secret) => {
    setPasswordInput(secret);
    setActiveTab('analyzer');
  };

  const clearInput = () => {
    setPasswordInput('');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* ── Top Header Navigation ────────────────────────────────────────── */}
      <header className="sticky top-0 z-30 bg-slate-900/80 backdrop-blur-xl border-b border-slate-800/80 px-4 sm:px-8 py-4 transition-all">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/dashboard')}
              className="p-2 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 text-slate-400 hover:text-white transition-colors flex items-center gap-2 group"
              title="Return to Dashboard"
            >
              <ArrowLeft className="w-5 h-5 group-hover:-translate-x-0.5 transition-transform" />
              <span className="hidden sm:inline text-xs font-semibold">Dashboard</span>
            </button>
            <div className="h-6 w-px bg-slate-800 hidden sm:block"></div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
                <KeyRound className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-black text-white tracking-tight flex items-center gap-2">
                  Password Security Lab
                  <span className="text-[10px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    Client-Side Engine
                  </span>
                </h1>
                <p className="text-xs text-slate-400 hidden md:block">
                  Entropy evaluation, pattern detection & cryptographically secure secret generation
                </p>
              </div>
            </div>
          </div>

          {/* Privacy Badge */}
          <div className="flex items-center gap-2">
            <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>100% Client-Side Password Analysis</span>
            </div>
          </div>
        </div>
      </header>

      {/* ── Hero Banner ─────────────────────────────────────────────────── */}
      <div className="relative overflow-hidden bg-gradient-to-b from-slate-900/50 to-slate-950 border-b border-slate-800/50 px-4 sm:px-8 py-8">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#08334410_1px,transparent_1px),linear-gradient(to_bottom,#08334410_1px,transparent_1px)] bg-[size:4rem_4rem] pointer-events-none"></div>
        <div className="max-w-7xl mx-auto relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="max-w-2xl space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Sparkles className="w-3.5 h-3.5" />
              Next-Gen Authentication Hardening
            </div>
            <h2 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
              Password Security Lab
            </h2>
            <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
              Strengthen your digital identity. Test password strength, discover security weaknesses, and generate stronger passwords — privately and securely.
            </p>
          </div>

          {/* Privacy Callout Pill */}
          <div className="bg-slate-900/90 border border-slate-800/80 rounded-2xl p-4 flex items-center gap-4 max-w-md shadow-xl">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center flex-shrink-0 text-cyan-400">
              <Lock className="w-5 h-5" />
            </div>
            <div className="text-xs space-y-1">
              <p className="font-bold text-white flex items-center gap-1.5">
                Zero Cloud Transmission
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              </p>
              <p className="text-slate-400 leading-normal">
                Your password never leaves this device. All strength checks and password generation happen locally in your browser via the Web Crypto API.
              </p>
            </div>
          </div>
        </div>

        {/* ── Sub Navigation Tabs ────────────────────────────────────────── */}
        <div className="max-w-7xl mx-auto mt-8 flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
          {[
            { id: 'analyzer', label: 'Strength Analyzer', icon: Shield },
            { id: 'generator', label: 'Password Generator', icon: KeyRound },
            { id: 'passphrase', label: 'Memorable Passphrase', icon: Layers },
            { id: 'checklist', label: 'Security Checklist', icon: CheckSquare },
            { id: 'education', label: 'What Makes a Password Strong?', icon: BookOpen },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-semibold text-xs whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/20 border border-cyan-400/30'
                    : 'bg-slate-900/80 text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 border border-slate-800'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Main Content Body ───────────────────────────────────────────── */}
      <main className="flex-1 max-w-7xl mx-auto w-full p-4 sm:p-8 space-y-8">
        {/* ════════════════════════════════════════════════════════════════════ */}
        {/* TAB 1: STRENGTH ANALYZER                                            */}
        {/* ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'analyzer' && (
          <div className="space-y-8">
            {/* Input & Gauge Hero Card */}
            <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
                {/* Left 8 Cols: Input field & controls */}
                <div className="lg:col-span-8 space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                        <Lock className="w-3.5 h-3.5 text-cyan-400" />
                        Enter Password to Evaluate
                      </label>
                      <span className="text-xs font-mono text-slate-400">
                        Length: <strong className="text-cyan-400">{passwordInput.length}</strong> chars
                      </span>
                    </div>

                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder="Type a password, PIN, or passphrase..."
                        autoComplete="off"
                        spellCheck="false"
                        className="w-full bg-slate-950/80 border border-slate-800 focus:border-cyan-500 rounded-2xl py-4 pl-5 pr-32 text-lg sm:text-xl font-mono text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 transition-all shadow-inner"
                      />

                      {/* Action buttons inside input */}
                      <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
                        {passwordInput && (
                          <button
                            onClick={clearInput}
                            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
                            title="Clear password input"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => setShowPassword(!showPassword)}
                          className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
                          title={showPassword ? 'Hide password' : 'Show password'}
                        >
                          {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                        {passwordInput && (
                          <button
                            onClick={() => copyToClipboard(passwordInput, setCopiedToast)}
                            className="p-2 rounded-xl text-slate-400 hover:text-cyan-400 hover:bg-slate-800/80 transition-colors"
                            title="Copy password"
                          >
                            {copiedToast ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Animated Linear Strength Meter Bar */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-400">Security Assessment:</span>
                        <span className={`px-2.5 py-0.5 rounded-full border text-xs font-bold ${theme.badge}`}>
                          {analysis.label}
                        </span>
                      </div>
                      <span className="font-mono text-slate-400">
                        Score: <strong className="text-white">{analysis.score}</strong> / 100
                      </span>
                    </div>

                    <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden p-0.5 border border-slate-800">
                      <motion.div
                        className={`h-full rounded-full ${theme.bar} transition-colors duration-500`}
                        initial={{ width: 0 }}
                        animate={{ width: `${analysis.scorePercent}%` }}
                        transition={{ type: 'spring', stiffness: 120, damping: 20 }}
                      />
                    </div>
                  </div>

                  {/* Character categories chips */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2">
                    {[
                      { label: 'Lowercase (a-z)', count: analysis.charSets.lowercase, active: analysis.charSets.lowercase > 0 },
                      { label: 'Uppercase (A-Z)', count: analysis.charSets.uppercase, active: analysis.charSets.uppercase > 0 },
                      { label: 'Numbers (0-9)', count: analysis.charSets.numbers, active: analysis.charSets.numbers > 0 },
                      { label: 'Symbols (!@#)', count: analysis.charSets.symbols, active: analysis.charSets.symbols > 0 },
                    ].map((set, idx) => (
                      <div
                        key={idx}
                        className={`px-3 py-2 rounded-xl border text-xs font-mono flex items-center justify-between transition-colors ${
                          set.active
                            ? 'bg-slate-950 border-cyan-500/30 text-cyan-300'
                            : 'bg-slate-950/50 border-slate-800/60 text-slate-500'
                        }`}
                      >
                        <span className="truncate">{set.label}</span>
                        <span className="font-bold">{set.count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right 4 Cols: Speedometer / Circular Gauge */}
                <div className="lg:col-span-4 flex flex-col items-center justify-center p-6 bg-slate-950/60 rounded-2xl border border-slate-800/80">
                  <div className="relative w-44 h-44 flex items-center justify-center">
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                      {/* Background ring */}
                      <circle
                        cx="60"
                        cy="60"
                        r="50"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="8"
                        className="text-slate-800"
                      />
                      {/* Animated indicator ring */}
                      <motion.circle
                        cx="60"
                        cy="60"
                        r="50"
                        fill="none"
                        strokeWidth="8"
                        strokeLinecap="round"
                        className={theme.ring}
                        strokeDasharray={2 * Math.PI * 50}
                        initial={{ strokeDashoffset: 2 * Math.PI * 50 }}
                        animate={{
                          strokeDashoffset:
                            2 * Math.PI * 50 - (analysis.scorePercent / 100) * (2 * Math.PI * 50),
                        }}
                        transition={{ type: 'spring', stiffness: 90, damping: 15 }}
                      />
                    </svg>

                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className="text-3xl font-black font-mono text-white tracking-tight">
                        {analysis.isEmpty ? '--' : `${analysis.score}%`}
                      </span>
                      <span className={`text-xs font-bold uppercase tracking-wider mt-1 ${theme.text}`}>
                        {analysis.label}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {analysis.isPassphrase ? 'Passphrase' : `${analysis.entropyBits} bits`}
                      </span>
                    </div>
                  </div>

                  <p className="text-center text-xs text-slate-400 mt-3 font-medium">
                    {analysis.isEmpty
                      ? 'Type in the box to receive real-time heuristic feedback'
                      : `Estimated Shannon Entropy: ${analysis.shannonBits} bits`}
                  </p>
                </div>
              </div>
            </div>

            {/* Crack Times & Entropy Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {[
                {
                  title: 'Online Throttled Attack',
                  rate: '1,000 guesses / sec',
                  time: analysis.crackTimes.online,
                  desc: 'Typical web login endpoint with basic rate limiting & CAPTCHA safeguards.',
                  icon: Zap,
                  accent: 'cyan',
                },
                {
                  title: 'Slow Hash (Argon2 / bcrypt)',
                  rate: '10,000 guesses / sec',
                  time: analysis.crackTimes.slowHash,
                  desc: 'Offline attacker brute-forcing an encrypted database dump on a workstation.',
                  icon: Cpu,
                  accent: 'blue',
                },
                {
                  title: 'Fast GPU Cluster (MD5 / NTLM)',
                  rate: '100 Billion guesses / sec',
                  time: analysis.crackTimes.fastGpu,
                  desc: 'State-of-the-art supercomputer GPU farm running Hashcat mask attacks.',
                  icon: Terminal,
                  accent: 'purple',
                },
              ].map((item, idx) => (
                <div
                  key={idx}
                  className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-2xl p-6 shadow-xl relative overflow-hidden group hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs font-mono font-bold uppercase text-slate-400 tracking-wider">
                      {item.title}
                    </span>
                    <item.icon className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                  </div>
                  <div className="text-xl sm:text-2xl font-black font-mono text-white tracking-tight mb-1">
                    {item.time}
                  </div>
                  <div className="text-xs font-mono text-cyan-400 mb-3">{item.rate}</div>
                  <p className="text-xs text-slate-400 leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>

            {/* Granular Security Indicators Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Left 7 Cols: Detailed Criteria Breakdown */}
              <div className="lg:col-span-7 bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-xl space-y-6">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <CheckSquare className="w-5 h-5 text-cyan-400" />
                    Deep Heuristic Analysis
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Granular validation across length, dictionary leaks, keyboard walks, and character predictability.
                  </p>
                </div>

                <div className="space-y-3">
                  {analysis.indicators.map((ind) => (
                    <div
                      key={ind.id}
                      className={`p-4 rounded-2xl border transition-all flex items-start justify-between gap-4 ${
                        ind.passed
                          ? 'bg-slate-950/60 border-emerald-500/20'
                          : ind.critical
                          ? 'bg-rose-500/5 border-rose-500/20'
                          : 'bg-slate-950/40 border-slate-800'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div className="mt-0.5">
                          {ind.passed ? (
                            <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                          ) : ind.critical ? (
                            <XCircle className="w-5 h-5 text-rose-400 flex-shrink-0" />
                          ) : (
                            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />
                          )}
                        </div>
                        <div>
                          <p className="font-bold text-sm text-white">{ind.label}</p>
                          <p className="text-xs text-slate-400 mt-0.5">{ind.info}</p>
                        </div>
                      </div>
                      <div className="text-right flex-shrink-0">
                        <span
                          className={`text-xs font-mono font-bold px-2 py-0.5 rounded-full ${
                            ind.passed
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : ind.critical
                              ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {ind.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right 5 Cols: Warnings & Actionable Suggestions */}
              <div className="lg:col-span-5 space-y-6">
                {/* Warnings card if any */}
                {analysis.warnings.length > 0 && (
                  <div className="bg-rose-500/10 border border-rose-500/30 rounded-3xl p-6 shadow-xl space-y-3">
                    <h4 className="text-sm font-bold text-rose-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-rose-400" />
                      Identified Vulnerabilities ({analysis.warnings.length})
                    </h4>
                    <ul className="space-y-2 text-xs text-rose-200">
                      {analysis.warnings.map((w, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-rose-400 font-bold">•</span>
                          <span>{w}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Suggestions Card */}
                <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 shadow-xl space-y-4">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-cyan-400" />
                    Recommended Actions
                  </h4>
                  <div className="space-y-2.5">
                    {analysis.suggestions.map((sug, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5"
                      >
                        <ChevronDown className="w-4 h-4 text-cyan-400 -rotate-90 flex-shrink-0 mt-0.5" />
                        <span>{sug}</span>
                      </div>
                    ))}
                  </div>

                  {/* Button to quick switch to Generator */}
                  <div className="pt-2">
                    <button
                      onClick={() => setActiveTab('generator')}
                      className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold text-xs flex items-center justify-center gap-2 hover:opacity-95 transition-opacity shadow-lg shadow-cyan-500/20"
                    >
                      <KeyRound className="w-4 h-4" />
                      Generate a Stronger Password Now
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════ */}
        {/* TAB 2: INTELLIGENT PASSWORD GENERATOR                               */}
        {/* ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'generator' && (
          <div className="space-y-8">
            <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
              <div className="max-w-3xl mx-auto space-y-8">
                {/* Result Box */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      Generated Secure Secret
                    </label>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400">
                        Strength: <strong className="text-cyan-400">{genAnalysis.label}</strong> ({genAnalysis.score}%)
                      </span>
                    </div>
                  </div>

                  <div className="relative">
                    <div className="w-full bg-slate-950/90 border border-slate-800 rounded-2xl py-5 px-6 font-mono text-xl sm:text-2xl text-white tracking-wider break-all shadow-inner select-all">
                      {generatedPassword || 'Generating...'}
                    </div>

                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2">
                      <button
                        onClick={handleGeneratePassword}
                        className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                        title="Regenerate new password"
                      >
                        <RefreshCw className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => copyToClipboard(generatedPassword, setGenCopied)}
                        className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 transition-all ${
                          genCopied
                            ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/30'
                            : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:opacity-95 shadow-lg shadow-cyan-500/20'
                        }`}
                      >
                        {genCopied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                        <span>{genCopied ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Actions under result */}
                  <div className="flex items-center justify-between mt-3 text-xs">
                    <span className="text-slate-500 font-mono">
                      Entropy: {genAnalysis.entropyBits} bits · Unbiased Web Crypto API
                    </span>
                    <button
                      onClick={() => handleTestInAnalyzer(generatedPassword)}
                      className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors flex items-center gap-1"
                    >
                      Audit in Strength Analyzer →
                    </button>
                  </div>
                </div>

                {/* Configuration Controls */}
                <div className="bg-slate-950/70 border border-slate-800/80 rounded-2xl p-6 space-y-6">
                  {/* Length Slider */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-white flex items-center gap-2">
                        <Sliders className="w-4 h-4 text-cyan-400" />
                        Password Length
                      </span>
                      <span className="text-base font-black font-mono px-3 py-1 rounded-xl bg-slate-900 border border-slate-700 text-cyan-400">
                        {genLength} chars
                      </span>
                    </div>

                    <input
                      type="range"
                      min="8"
                      max="64"
                      value={genLength}
                      onChange={(e) => {
                        setGenLength(Number(e.target.value));
                        handleGeneratePassword();
                      }}
                      className="w-full accent-cyan-500 h-2 bg-slate-800 rounded-lg cursor-pointer"
                    />

                    <div className="flex justify-between text-[11px] font-mono text-slate-500">
                      <span>8 (Min)</span>
                      <span>16 (Recommended)</span>
                      <span>32 (High)</span>
                      <span>64 (Max)</span>
                    </div>
                  </div>

                  {/* Toggles */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-slate-800/80">
                    {[
                      {
                        id: 'upper',
                        label: 'Uppercase Letters (A-Z)',
                        checked: genUpper,
                        setter: setGenUpper,
                      },
                      {
                        id: 'lower',
                        label: 'Lowercase Letters (a-z)',
                        checked: genLower,
                        setter: setGenLower,
                      },
                      {
                        id: 'num',
                        label: 'Numbers (0-9)',
                        checked: genNumbers,
                        setter: setGenNumbers,
                      },
                      {
                        id: 'sym',
                        label: 'Symbols (!@#$%^&*)',
                        checked: genSymbols,
                        setter: setGenSymbols,
                      },
                    ].map((opt) => (
                      <label
                        key={opt.id}
                        className="flex items-center gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition-all"
                      >
                        <input
                          type="checkbox"
                          checked={opt.checked}
                          onChange={(e) => {
                            opt.setter(e.target.checked);
                            setTimeout(handleGeneratePassword, 0);
                          }}
                          className="checkbox checkbox-sm checkbox-info rounded-md"
                        />
                        <span className="text-xs font-semibold text-slate-300">{opt.label}</span>
                      </label>
                    ))}
                  </div>

                  {/* Exclude Ambiguous */}
                  <div className="pt-2 border-t border-slate-800/80">
                    <label className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={genNoAmbiguous}
                        onChange={(e) => {
                          setGenNoAmbiguous(e.target.checked);
                          setTimeout(handleGeneratePassword, 0);
                        }}
                        className="checkbox checkbox-sm checkbox-info rounded-md"
                      />
                      <div>
                        <span className="text-xs font-bold text-white block">
                          Exclude Ambiguous Characters
                        </span>
                        <span className="text-[11px] text-slate-500">
                          Removes confusing characters: <code className="text-cyan-400 font-mono">0, O, l, 1, I, |</code>
                        </span>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Regenerate Button */}
                <button
                  onClick={handleGeneratePassword}
                  className="w-full py-4 rounded-2xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:opacity-95 text-white font-black text-sm tracking-wide shadow-xl shadow-cyan-500/20 flex items-center justify-center gap-2 transition-all"
                >
                  <RefreshCw className="w-5 h-5" />
                  Generate New Cryptographic Password
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════ */}
        {/* TAB 3: MEMORABLE PASSPHRASE GENERATOR                               */}
        {/* ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'passphrase' && (
          <div className="space-y-8">
            <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
              <div className="max-w-3xl mx-auto space-y-8">
                {/* Intro banner */}
                <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-start gap-3">
                  <Info className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <div className="text-xs text-slate-300 leading-relaxed">
                    <strong className="text-white">Why Passphrases?</strong> Combining 4 or 5 unrelated words provides massive combinatorial entropy while remaining effortlessly memorizable for humans. It defeats modern dictionary rules and GPU brute-forcing simultaneously.
                  </div>
                </div>

                {/* Result Display Box */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Layers className="w-3.5 h-3.5 text-cyan-400" />
                      Generated Diceware Passphrase
                    </label>
                    <span className="text-xs font-mono text-cyan-400">
                      Entropy: <strong>{passAnalysis.entropyBits} bits</strong>
                    </span>
                  </div>

                  <div className="relative">
                    <div className="w-full bg-slate-950/90 border border-slate-800 rounded-2xl py-5 px-6 font-mono text-xl sm:text-2xl text-white tracking-wider break-all shadow-inner select-all">
                      {generatedPassphrase || 'Generating...'}
                    </div>

                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2">
                      <button
                        onClick={handleGeneratePassphrase}
                        className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                        title="Regenerate passphrase"
                      >
                        <RefreshCw className="w-5 h-5" />
                      </button>
                      <button
                        onClick={() => copyToClipboard(generatedPassphrase, setPassCopied)}
                        className={`px-4 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 transition-all ${
                          passCopied
                            ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/30'
                            : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:opacity-95 shadow-lg shadow-cyan-500/20'
                        }`}
                      >
                        {passCopied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                        <span>{passCopied ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between mt-3 text-xs">
                    <span className="text-slate-500 font-mono">
                      Estimated Crack Time: {passAnalysis.crackTimes.fastGpu}
                    </span>
                    <button
                      onClick={() => handleTestInAnalyzer(generatedPassphrase)}
                      className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors flex items-center gap-1"
                    >
                      Audit in Strength Analyzer →
                    </button>
                  </div>
                </div>

                {/* Passphrase Controls */}
                <div className="bg-slate-950/70 border border-slate-800/80 rounded-2xl p-6 space-y-6">
                  {/* Word count slider */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-white flex items-center gap-2">
                        <Sliders className="w-4 h-4 text-cyan-400" />
                        Number of Words
                      </span>
                      <span className="text-base font-black font-mono px-3 py-1 rounded-xl bg-slate-900 border border-slate-700 text-cyan-400">
                        {passWordCount} words
                      </span>
                    </div>

                    <input
                      type="range"
                      min="3"
                      max="8"
                      value={passWordCount}
                      onChange={(e) => {
                        setPassWordCount(Number(e.target.value));
                        setTimeout(handleGeneratePassphrase, 0);
                      }}
                      className="w-full accent-cyan-500 h-2 bg-slate-800 rounded-lg cursor-pointer"
                    />

                    <div className="flex justify-between text-[11px] font-mono text-slate-500">
                      <span>3 Words (Fast)</span>
                      <span>4 Words (Balanced)</span>
                      <span>6 Words (Paranoid)</span>
                      <span>8 Words (Maximum)</span>
                    </div>
                  </div>

                  {/* Separator and Capitalization */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-slate-800/80">
                    <div>
                      <label className="text-xs font-bold text-slate-300 block mb-2">
                        Word Separator
                      </label>
                      <select
                        value={passSeparator}
                        onChange={(e) => {
                          setPassSeparator(e.target.value);
                          setTimeout(handleGeneratePassphrase, 0);
                        }}
                        className="select select-bordered select-sm w-full bg-slate-900 text-white border-slate-700 rounded-xl"
                      >
                        <option value="-">Hyphen (-)</option>
                        <option value="_">Underscore (_)</option>
                        <option value=".">Period (.)</option>
                        <option value=" ">Space ( )</option>
                        <option value="#">Hash (#)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-xs font-bold text-slate-300 block mb-2">
                        Capitalization Style
                      </label>
                      <select
                        value={passCapitalize}
                        onChange={(e) => {
                          setPassCapitalize(e.target.value);
                          setTimeout(handleGeneratePassphrase, 0);
                        }}
                        className="select select-bordered select-sm w-full bg-slate-900 text-white border-slate-700 rounded-xl"
                      >
                        <option value="title">TitleCase (e.g. Amber-Falcon)</option>
                        <option value="lower">lowercase (e.g. amber-falcon)</option>
                        <option value="upper">UPPERCASE (e.g. AMBER-FALCON)</option>
                      </select>
                    </div>
                  </div>

                  {/* Suffix options */}
                  <div className="pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <label className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={passIncludeSuffix}
                        onChange={(e) => {
                          setPassIncludeSuffix(e.target.checked);
                          setTimeout(handleGeneratePassphrase, 0);
                        }}
                        className="checkbox checkbox-sm checkbox-info rounded-md"
                      />
                      <span className="text-xs font-bold text-white">Append Random Suffix</span>
                    </label>

                    {passIncludeSuffix && (
                      <div className="flex items-center gap-2">
                        {['number', 'symbol', 'both'].map((type) => (
                          <button
                            key={type}
                            onClick={() => {
                              setPassSuffixType(type);
                              setTimeout(handleGeneratePassphrase, 0);
                            }}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize border transition-all ${
                              passSuffixType === type
                                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                                : 'bg-slate-900 text-slate-400 border-slate-800'
                            }`}
                          >
                            {type}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <button
                  onClick={handleGeneratePassphrase}
                  className="w-full py-4 rounded-2xl bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:opacity-95 text-white font-black text-sm tracking-wide shadow-xl shadow-cyan-500/20 flex items-center justify-center gap-2 transition-all"
                >
                  <RefreshCw className="w-5 h-5" />
                  Generate New Memorable Passphrase
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════ */}
        {/* TAB 4: PASSWORD SECURITY CHECKLIST                                  */}
        {/* ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'checklist' && (
          <div className="space-y-8">
            <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
              <div>
                <h3 className="text-xl font-black text-white flex items-center gap-2">
                  <CheckSquare className="w-6 h-6 text-cyan-400" />
                  Your Security Checklist
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Evaluate your overall password hygiene and identity protection posture.
                </p>
              </div>

              {/* Informational Callout */}
              <div className="p-4 rounded-2xl bg-blue-500/10 border border-blue-500/20 text-xs text-slate-300 flex items-start gap-3">
                <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <p>
                  A strong password is only one part of account security. Unique passwords and multifactor authentication provide additional protection against breaches, credential stuffing, and phishing.
                </p>
              </div>

              {/* Interactive Checklist Items */}
              <div className="space-y-3">
                {[
                  {
                    key: 'length',
                    title: 'Use a long password or passphrase (14+ characters)',
                    desc: 'Mathematical entropy scales exponentially with length. Aim for at least 14 characters.',
                    isLive: true,
                    status: passwordInput.length >= 14,
                    feedback: passwordInput.length >= 14 ? 'Verified with current password' : 'Current password is under 14 chars',
                  },
                  {
                    key: 'common',
                    title: 'Avoid common and predictable passwords',
                    desc: 'Do not use dictionary words, sequential numbers (1234), or keyboard walks (qwerty).',
                    isLive: true,
                    status: passwordInput.length > 0 && !analysis.warnings.some(w => w.includes('common') || w.includes('pattern')),
                    feedback: 'Checked against leaked pattern databases',
                  },
                  {
                    key: 'unique',
                    title: 'Do not reuse passwords across accounts',
                    desc: 'If one website leaks your password, credential stuffing bots will try it on your email and banking.',
                    isLive: false,
                    stateKey: 'uniquePerAccount',
                  },
                  {
                    key: 'personal',
                    title: 'Avoid personal information (birthdays, names, phone numbers)',
                    desc: 'Open-source intelligence (OSINT) scripts scrape social media to guess security credentials.',
                    isLive: false,
                    stateKey: 'noPersonalInfo',
                  },
                  {
                    key: 'manager',
                    title: 'Use a verified password manager',
                    desc: 'Software like Bitwarden or 1Password generates and stores unique, complex credentials securely.',
                    isLive: false,
                    stateKey: 'usesPasswordManager',
                  },
                  {
                    key: 'mfa',
                    title: 'Enable Multi-Factor Authentication (MFA / 2FA)',
                    desc: 'Hardware keys (YubiKey) or TOTP apps stop account takeovers even if your password is stolen.',
                    isLive: false,
                    stateKey: 'mfaEnabled',
                  },
                ].map((item, idx) => {
                  const isChecked = item.isLive ? item.status : checklistState[item.stateKey];

                  return (
                    <div
                      key={idx}
                      onClick={() => {
                        if (!item.isLive) {
                          setChecklistState((prev) => ({
                            ...prev,
                            [item.stateKey]: !prev[item.stateKey],
                          }));
                        }
                      }}
                      className={`p-4 rounded-2xl border transition-all flex items-start gap-4 ${
                        item.isLive ? '' : 'cursor-pointer hover:border-slate-700'
                      } ${
                        isChecked
                          ? 'bg-emerald-500/5 border-emerald-500/20'
                          : 'bg-slate-950/50 border-slate-800'
                      }`}
                    >
                      <button className="mt-0.5 text-slate-400">
                        {isChecked ? (
                          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                        ) : (
                          <Square className="w-5 h-5 text-slate-600" />
                        )}
                      </button>

                      <div className="flex-1">
                        <p className={`text-sm font-bold ${isChecked ? 'text-white' : 'text-slate-300'}`}>
                          {item.title}
                        </p>
                        <p className="text-xs text-slate-400 mt-0.5">{item.desc}</p>
                        {item.isLive && (
                          <span className={`inline-block mt-2 text-[11px] font-mono px-2 py-0.5 rounded-full ${
                            isChecked ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'
                          }`}>
                            {item.feedback}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════════ */}
        {/* TAB 5: WHAT MAKES A PASSWORD STRONG? & MYTHS VS FACTS               */}
        {/* ════════════════════════════════════════════════════════════════════ */}
        {activeTab === 'education' && (
          <div className="space-y-8">
            {/* Core Concepts Grid */}
            <div className="space-y-4">
              <h3 className="text-xl font-black text-white flex items-center gap-2">
                <BookOpen className="w-6 h-6 text-cyan-400" />
                What Makes a Password Strong?
              </h3>
              <p className="text-xs text-slate-400">
                Core cybersecurity principles governing modern authentication and mathematical resistance.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 pt-2">
                {CONCEPTS.map((concept, idx) => {
                  const Icon = concept.icon;
                  return (
                    <div
                      key={idx}
                      className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-2xl p-6 shadow-xl space-y-3 hover:border-slate-700 transition-all"
                    >
                      <div className="flex items-center justify-between">
                        <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center">
                          <Icon className="w-5 h-5" />
                        </div>
                        <span className="text-[10px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-slate-800 text-slate-400">
                          {concept.tag}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-white">{concept.title}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed">{concept.desc}</p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Interactive Myth vs Fact Section */}
            <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
              <div>
                <h3 className="text-xl font-black text-white flex items-center gap-2">
                  <HelpCircle className="w-6 h-6 text-amber-400" />
                  Interactive Password Myth vs. Fact
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Common misconceptions debunked by security engineers. Click any card to reveal the engineering truth.
                </p>
              </div>

              <div className="space-y-4">
                {MYTHS_AND_FACTS.map((item) => {
                  const isExpanded = expandedMyth === item.id;
                  return (
                    <div
                      key={item.id}
                      onClick={() => setExpandedMyth(isExpanded ? null : item.id)}
                      className="p-5 rounded-2xl bg-slate-950/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all space-y-3"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex items-start gap-3">
                          <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] font-mono font-bold uppercase mt-0.5">
                            Myth
                          </span>
                          <span className="text-sm font-bold text-white">{item.myth}</span>
                        </div>
                        <ChevronDown
                          className={`w-5 h-5 text-slate-400 transition-transform ${
                            isExpanded ? 'rotate-180 text-cyan-400' : ''
                          }`}
                        />
                      </div>

                      <AnimatePresence>
                        {isExpanded && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="pt-3 border-t border-slate-800/80 space-y-2 text-xs"
                          >
                            <div className="flex items-start gap-3 text-cyan-300">
                              <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-[10px] font-mono font-bold uppercase mt-0.5">
                                Fact
                              </span>
                              <span className="leading-relaxed">{item.fact}</span>
                            </div>
                            <div className="pl-12 text-slate-400">
                              <strong className="text-slate-300">Takeaway:</strong> {item.takeaway}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default PasswordSecurityScreen;
