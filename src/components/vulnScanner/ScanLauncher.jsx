import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Globe, ShieldCheck, Lock, Cookie, Server, FileWarning, Bug, Database, Radar,
  History, ArrowRight, AlertTriangle, CheckCircle2, Loader2,
} from 'lucide-react';
import { PROFILES, RISK_LEVEL, SCAN_STATUS_LABEL, formatDate } from './constants';

const CHECK_AREAS = [
  { icon: Lock, title: 'TLS & HTTPS', text: 'Certificate validity, hostname, trust chain, TLS 1.0–1.3 support, HTTP→HTTPS redirects.' },
  { icon: ShieldCheck, title: 'Security headers', text: 'CSP directive analysis, HSTS, clickjacking, MIME sniffing, referrer and isolation policies.' },
  { icon: Cookie, title: 'Cookies & CORS', text: 'Secure / HttpOnly / SameSite attributes, reflected origins, credentials and preflights.' },
  { icon: FileWarning, title: 'Exposure', text: 'Version banners, debug pages, directory listings, .env / .git and other sensitive files.' },
  { icon: Bug, title: 'Safe vulnerability probes', text: 'Reflected-input (XSS) indicators, error-based SQL injection indicators, open redirects.' },
  { icon: Database, title: 'CVE intelligence', text: 'Detected software versions correlated with the NIST National Vulnerability Database.' },
];

const fade = (i = 0) => ({ initial: { opacity: 0, y: 14 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.35, delay: i * 0.05 } });

const ScanLauncher = ({ onStart, starting, error, history, onOpenScan, profileChecks }) => {
  const [url, setUrl] = useState('');
  const [profile, setProfile] = useState('standard');
  const [authorized, setAuthorized] = useState(false);
  const canStart = url.trim().length > 3 && authorized && !starting;

  const submit = (event) => {
    event.preventDefault();
    if (canStart) onStart({ url: url.trim(), profile });
  };

  return (
    <div className="space-y-8">
      {/* Hero */}
      <motion.section {...fade()} className="relative overflow-hidden rounded-3xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 p-6 sm:p-10">
        <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" aria-hidden="true" />
        <div className="relative max-w-3xl">
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
            <Radar className="h-3.5 w-3.5" /> Web Vulnerability Assessment
          </span>
          <h1 className="mt-4 text-3xl font-black tracking-tight text-white sm:text-4xl">Vulnerability Scanner</h1>
          <p className="mt-3 text-sm leading-relaxed text-slate-400 sm:text-base">
            Run real, evidence-based security checks against a website you own or are authorised to test. Every finding comes
            from an actual response, handshake or intelligence source — and is labelled as confirmed, a misconfiguration, or a
            potential issue that needs manual verification.
          </p>
        </div>

        <form onSubmit={submit} className="relative mt-8 space-y-5">
          <label className="block">
            <span className="mb-2 block text-xs font-bold uppercase tracking-wider text-slate-400">Target URL</span>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <Globe className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-website.com/page?id=1"
                  maxLength={2048}
                  className="w-full rounded-2xl border border-slate-700 bg-slate-950/80 py-4 pl-12 pr-4 font-mono text-sm text-white placeholder-slate-600 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10"
                  aria-label="Target URL"
                />
              </div>
              <button
                type="submit"
                disabled={!canStart}
                className="inline-flex items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-cyan-500 to-blue-600 px-7 py-4 text-sm font-bold text-white shadow-lg shadow-cyan-900/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {starting ? <Loader2 className="h-5 w-5 animate-spin" /> : <ArrowRight className="h-5 w-5" />}
                {starting ? 'Starting…' : 'Start scan'}
              </button>
            </div>
            <span className="mt-2 block text-xs text-slate-500">
              Include query parameters (e.g. <code className="text-slate-400">/products?id=1</code>) to let the safe injection probes test them.
            </span>
          </label>

          {/* Profiles */}
          <fieldset>
            <legend className="mb-3 text-xs font-bold uppercase tracking-wider text-slate-400">Assessment profile</legend>
            <div className="grid gap-3 md:grid-cols-3">
              {PROFILES.map((p) => {
                const selected = profile === p.id;
                const checks = profileChecks?.[p.id];
                return (
                  <button
                    type="button"
                    key={p.id}
                    onClick={() => setProfile(p.id)}
                    aria-pressed={selected}
                    className={`relative rounded-2xl border p-4 text-left transition ${selected ? 'border-cyan-500/70 bg-cyan-500/10 shadow-lg shadow-cyan-900/20' : 'border-slate-800 bg-slate-950/40 hover:border-slate-600'}`}
                  >
                    {p.recommended && <span className="absolute right-3 top-3 rounded-full bg-cyan-500/15 px-2 py-0.5 text-[10px] font-bold uppercase text-cyan-300">Recommended</span>}
                    <span className="block text-sm font-bold text-white">{p.name}</span>
                    <span className="mt-0.5 block text-xs font-medium text-cyan-300/80">{p.intensity}</span>
                    <span className="mt-2 block text-xs leading-relaxed text-slate-400">{p.description}</span>
                    {checks && <span className="mt-2 block text-[11px] text-slate-500">{checks.length} checks</span>}
                  </button>
                );
              })}
            </div>
          </fieldset>

          {/* Authorization */}
          <label className={`flex cursor-pointer items-start gap-3 rounded-2xl border p-4 transition ${authorized ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-amber-500/30 bg-amber-500/5'}`}>
            <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="mt-0.5 h-5 w-5 shrink-0 accent-cyan-500" />
            <span className="text-sm text-slate-300">
              <span className="font-bold text-white">I own this website or have explicit written permission to test it.</span>{' '}
              The scanner sends real (non-destructive) requests to the target. Scanning systems without permission may be illegal.
            </span>
          </label>

          {error && (
            <div role="alert" className="flex items-start gap-3 rounded-2xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </form>
      </motion.section>

      {/* What it checks */}
      <section>
        <h2 className="mb-4 text-sm font-bold uppercase tracking-wider text-slate-400">What the scanner checks</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {CHECK_AREAS.map(({ icon: Icon, title, text }, i) => (
            <motion.div key={title} {...fade(i)} className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
              <Icon className="h-5 w-5 text-cyan-400" />
              <h3 className="mt-3 text-sm font-bold text-white">{title}</h3>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{text}</p>
            </motion.div>
          ))}
        </div>
        <p className="mt-3 flex items-center gap-2 text-xs text-slate-500">
          <Server className="h-3.5 w-3.5" /> No crawling, brute force, exploitation or data extraction is performed. Path traversal and authenticated areas are not tested.
        </p>
      </section>

      {/* History */}
      <section>
        <h2 className="mb-4 flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-slate-400">
          <History className="h-4 w-4" /> Recent scans
        </h2>
        {history === null ? (
          <p className="text-sm text-slate-500">Loading history…</p>
        ) : history.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">No scans yet. Your completed assessments will appear here.</p>
        ) : (
          <ul className="divide-y divide-slate-800 overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/50">
            {history.map((scan) => {
              const level = scan.summary?.riskLevel && RISK_LEVEL[scan.summary.riskLevel];
              return (
                <li key={scan.id}>
                  <button type="button" onClick={() => onOpenScan(scan.id)} className="flex w-full items-center gap-4 px-4 py-3 text-left transition hover:bg-slate-800/50 sm:px-5">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-sm font-black text-white" style={{ background: level ? `${level.color}26` : '#1e293b', color: level?.color }}>
                      {scan.summary ? scan.summary.securityScore : scan.scanStatus === 'running' ? <Loader2 className="h-4 w-4 animate-spin" /> : '—'}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-sm text-slate-200">{scan.targetUrl}</span>
                      <span className="block text-xs text-slate-500">
                        {formatDate(scan.startedAt)} · {scan.profile} · {SCAN_STATUS_LABEL[scan.scanStatus] || scan.scanStatus}
                        {scan.summary ? ` · ${scan.summary.totalFindings} findings` : ''}
                      </span>
                    </span>
                    {scan.scanStatus === 'completed' ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" /> : <ArrowRight className="h-4 w-4 shrink-0 text-slate-600" />}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
};

export default ScanLauncher;
