import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Loader2, CheckCircle2, AlertTriangle, MinusCircle, XCircle, Circle, StopCircle, Wifi, WifiOff, Globe } from 'lucide-react';
import { SEVERITY, SEVERITY_ORDER, STATUS_STYLE, formatDuration } from './constants';

const StatusIcon = ({ status }) => {
  if (status === 'running') return <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />;
  if (status === 'passed') return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
  if (status === 'issues') return <AlertTriangle className="h-4 w-4 text-amber-400" />;
  if (status === 'error') return <XCircle className="h-4 w-4 text-rose-400" />;
  if (status === 'skipped' || status === 'cancelled' || status === 'inconclusive') return <MinusCircle className="h-4 w-4 text-slate-500" />;
  return <Circle className="h-4 w-4 text-slate-700" />;
};

/** Elapsed time ticks locally between server updates, anchored to the server's value. */
const useElapsed = (serverElapsed, running) => {
  const [anchor, setAnchor] = useState({ value: serverElapsed || 0, at: Date.now() });
  const [, force] = useState(0);
  useEffect(() => setAnchor({ value: serverElapsed || 0, at: Date.now() }), [serverElapsed]);
  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => force((n) => n + 1), 500);
    return () => clearInterval(timer);
  }, [running]);
  return running ? anchor.value + (Date.now() - anchor.at) : anchor.value;
};

const LiveScan = ({ snapshot, onCancel, cancelling, connected }) => {
  const reduceMotion = useReducedMotion();
  const running = snapshot?.scanStatus === 'running';
  const elapsed = useElapsed(snapshot?.elapsedMs, running);
  if (!snapshot) return null;
  const percent = snapshot.total ? Math.round((snapshot.completed / snapshot.total) * 100) : 0;

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <section className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6 sm:p-8">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0">
            <p className="text-xs font-bold uppercase tracking-wider text-cyan-300">Assessment in progress · {snapshot.profile}</p>
            <h2 className="mt-2 flex items-center gap-2 truncate font-mono text-lg text-white sm:text-xl">
              <Globe className="h-5 w-5 shrink-0 text-slate-500" /> <span className="truncate">{snapshot.target}</span>
            </h2>
            <p className="mt-2 flex items-center gap-2 text-xs text-slate-500">
              {connected ? <Wifi className="h-3.5 w-3.5 text-emerald-400" /> : <WifiOff className="h-3.5 w-3.5 text-amber-400" />}
              {connected ? 'Live updates connected' : 'Live connection lost — polling for progress'}
            </p>
          </div>
          <button
            type="button"
            onClick={onCancel}
            disabled={!running || cancelling}
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-2.5 text-sm font-semibold text-rose-200 transition hover:bg-rose-500/20 disabled:opacity-40"
          >
            {cancelling ? <Loader2 className="h-4 w-4 animate-spin" /> : <StopCircle className="h-4 w-4" />} {cancelling ? 'Cancelling…' : 'Cancel scan'}
          </button>
        </div>

        {/* Progress */}
        <div className="mt-6">
          <div className="mb-2 flex items-end justify-between text-sm">
            <span className="text-slate-300">
              {snapshot.currentCheck ? <>Running: <span className="font-semibold text-white">{snapshot.currentCheck.label}</span></> : running ? 'Preparing…' : 'Finishing…'}
            </span>
            <span className="font-mono text-slate-400">{snapshot.completed}/{snapshot.total} checks</span>
          </div>
          <div className="h-2.5 overflow-hidden rounded-full bg-slate-800" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
              initial={false}
              animate={{ width: `${percent}%` }}
              transition={{ duration: reduceMotion ? 0 : 0.4 }}
            />
          </div>
        </div>

        {/* Stats */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            ['Elapsed', formatDuration(elapsed)],
            ['Requests sent', snapshot.requests],
            ['Findings so far', snapshot.findingsCount],
            ['Progress', `${percent}%`],
          ].map(([label, value]) => (
            <div key={label} className="rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
              <p className="mt-1 font-mono text-xl font-bold text-white">{value}</p>
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((sev) => (
            <span key={sev} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${SEVERITY[sev].badge}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY[sev].dot}`} /> {SEVERITY[sev].label}: {snapshot.bySeverity?.[sev] ?? 0}
            </span>
          ))}
        </div>
      </section>

      {/* Check list */}
      <section className="rounded-3xl border border-slate-800 bg-slate-900/50 p-4 sm:p-6">
        <h3 className="mb-3 px-2 text-xs font-bold uppercase tracking-wider text-slate-400">Executed checks</h3>
        <ol className="space-y-1">
          <AnimatePresence initial={false}>
            {snapshot.checks.map((check) => {
              const style = STATUS_STYLE[check.status] || STATUS_STYLE.pending;
              return (
                <motion.li
                  key={check.id}
                  layout={!reduceMotion}
                  className={`flex items-start gap-3 rounded-xl px-3 py-2.5 ${check.status === 'running' ? 'bg-cyan-500/5 ring-1 ring-cyan-500/30' : ''}`}
                >
                  <span className="mt-0.5"><StatusIcon status={check.status} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-x-2">
                      <span className={`text-sm font-medium ${check.status === 'pending' ? 'text-slate-500' : 'text-slate-200'}`}>{check.label}</span>
                      <span className="text-[11px] text-slate-600">{check.phase}</span>
                    </span>
                    {check.note && check.status !== 'running' && <span className="block break-words text-xs text-slate-500">{check.note}</span>}
                  </span>
                  <span className={`shrink-0 text-xs font-semibold ${style.className}`}>
                    {style.label}
                    {typeof check.durationMs === 'number' && check.status !== 'pending' && check.status !== 'running' ? ` · ${formatDuration(check.durationMs)}` : ''}
                  </span>
                </motion.li>
              );
            })}
          </AnimatePresence>
        </ol>
      </section>
    </motion.div>
  );
};

export default LiveScan;
