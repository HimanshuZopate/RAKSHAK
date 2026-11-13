import React, { useMemo, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import {
  Download, RotateCcw, ShieldCheck, Lock, Cpu, ListChecks, FileText, AlertTriangle, Info, CheckCircle2, MinusCircle, XCircle, Clock,
} from 'lucide-react';
import FindingCard from './FindingCard';
import { exportScanPdf } from './reportPdf';
import {
  RISK_LEVEL, SEVERITY, SEVERITY_ORDER, VERIFICATION, STATUS_STYLE, SCAN_STATUS_LABEL, formatDate, formatDuration,
} from './constants';

const Card = ({ title, icon: Icon, children, className = '', delay = 0 }) => {
  const reduceMotion = useReducedMotion();
  return (
    <motion.section
      initial={reduceMotion ? false : { opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
      className={`rounded-3xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6 ${className}`}
    >
      {title && (
        <h3 className="mb-4 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
          {Icon && <Icon className="h-4 w-4 text-cyan-400" />} {title}
        </h3>
      )}
      {children}
    </motion.section>
  );
};

const ScoreRing = ({ score, color }) => {
  const reduceMotion = useReducedMotion();
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  return (
    <svg viewBox="0 0 140 140" className="h-40 w-40" role="img" aria-label={`Security score ${score} out of 100`}>
      <circle cx="70" cy="70" r={radius} fill="none" stroke="#1e293b" strokeWidth="12" />
      <motion.circle
        cx="70" cy="70" r={radius} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
        strokeDasharray={circumference}
        initial={{ strokeDashoffset: reduceMotion ? circumference * (1 - score / 100) : circumference }}
        animate={{ strokeDashoffset: circumference * (1 - score / 100) }}
        transition={{ duration: reduceMotion ? 0 : 1.1, ease: 'easeOut' }}
        transform="rotate(-90 70 70)"
      />
      <text x="70" y="68" textAnchor="middle" className="fill-white" style={{ fontSize: 34, fontWeight: 900 }}>{score}</text>
      <text x="70" y="90" textAnchor="middle" className="fill-slate-400" style={{ fontSize: 11 }}>/ 100</text>
    </svg>
  );
};

const CheckIcon = ({ status }) => {
  if (status === 'passed') return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
  if (status === 'issues') return <AlertTriangle className="h-4 w-4 text-amber-400" />;
  if (status === 'error') return <XCircle className="h-4 w-4 text-rose-400" />;
  return <MinusCircle className="h-4 w-4 text-slate-500" />;
};

const ScanReport = ({ scan, onNewScan }) => {
  const [severityFilter, setSeverityFilter] = useState('all');
  const [verificationFilter, setVerificationFilter] = useState('all');
  const [openId, setOpenId] = useState(null);
  const [exporting, setExporting] = useState(false);
  const summary = scan.summary || {};
  const risk = RISK_LEVEL[summary.riskLevel] || RISK_LEVEL.minimal;
  const findings = useMemo(() => scan.findings || [], [scan.findings]);

  const filtered = useMemo(
    () => findings.filter((f) => (severityFilter === 'all' || f.severity === severityFilter) && (verificationFilter === 'all' || f.verification === verificationFilter)),
    [findings, severityFilter, verificationFilter]
  );
  const chartData = SEVERITY_ORDER.map((s) => ({ name: SEVERITY[s].label, key: s, count: summary.bySeverity?.[s] ?? 0 }));
  const remediation = useMemo(() => {
    const seen = new Set();
    return findings
      .filter((f) => f.severity !== 'info' && f.verification !== 'informational')
      .filter((f) => (seen.has(f.remediation) ? false : seen.add(f.remediation)))
      .slice(0, 8);
  }, [findings]);
  const headerRows = Object.entries(scan.headerSnapshot?.headers || {});
  const tls = scan.tls;
  const cert = tls?.certificate;

  const exportPdf = () => {
    setExporting(true);
    try {
      exportScanPdf(scan);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <p className="text-xs font-bold uppercase tracking-wider text-cyan-300">Security assessment report</p>
            <h2 className="mt-1 break-all font-mono text-lg text-white sm:text-xl">{scan.targetUrl}</h2>
            <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
              <span>Status: <span className="text-slate-300">{SCAN_STATUS_LABEL[scan.scanStatus] || scan.scanStatus}</span></span>
              <span>Profile: <span className="capitalize text-slate-300">{scan.profile}</span></span>
              <span><Clock className="mr-1 inline h-3 w-3" />{formatDate(scan.startedAt)}</span>
              <span>Duration: <span className="text-slate-300">{formatDuration(scan.durationMs)}</span></span>
              <span>Requests: <span className="text-slate-300">{scan.requestCount ?? '—'}</span></span>
              <span>Scanner v{scan.scannerVersion}</span>
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button type="button" onClick={exportPdf} disabled={exporting} className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2.5 text-sm font-bold text-white transition hover:brightness-110 disabled:opacity-50">
              <Download className="h-4 w-4" /> Export PDF
            </button>
            <button type="button" onClick={onNewScan} className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2.5 text-sm font-semibold text-slate-200 transition hover:border-slate-500">
              <RotateCcw className="h-4 w-4" /> New scan
            </button>
          </div>
        </div>
        {scan.errorMessage && (
          <p role="alert" className="mt-4 flex items-start gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> {scan.errorMessage}
          </p>
        )}
        {scan.scanStatus !== 'completed' && !scan.errorMessage && (
          <p className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
            This scan did not run to completion ({SCAN_STATUS_LABEL[scan.scanStatus]}). Results below cover only the checks that finished.
          </p>
        )}
      </Card>

      {/* Score + distribution */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Security score" icon={ShieldCheck} delay={0.05}>
          <div className="flex flex-col items-center text-center">
            <ScoreRing score={summary.securityScore ?? 0} color={risk.color} />
            <span className="mt-2 rounded-full px-3 py-1 text-sm font-bold" style={{ background: `${risk.color}22`, color: risk.color }}>{risk.label}</span>
            <p className="mt-3 text-xs text-slate-500">Risk score {summary.riskScore ?? 0}/100 · based on {summary.checksCompleted ?? 0} completed checks. Not a certification.</p>
          </div>
        </Card>

        <Card title="Severity distribution" icon={ListChecks} delay={0.1}>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: 'rgba(148,163,184,0.08)' }} contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 12, color: '#e2e8f0' }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {chartData.map((d) => <Cell key={d.key} fill={SEVERITY[d.key].color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Evidence & coverage" icon={FileText} delay={0.15}>
          <dl className="grid grid-cols-2 gap-3">
            {[
              ['Total findings', summary.totalFindings ?? 0, 'text-white'],
              ['Confirmed / config', summary.confirmed ?? 0, 'text-rose-200'],
              ['Potential', summary.potential ?? 0, 'text-violet-200'],
              ['Informational', summary.byVerification?.informational ?? 0, 'text-slate-300'],
              ['Checks completed', `${summary.checksCompleted ?? 0}/${summary.checksTotal ?? 0}`, 'text-emerald-300'],
              ['Inconclusive / skipped', `${summary.checksInconclusive ?? 0} / ${summary.checksSkipped ?? 0}`, 'text-slate-300'],
            ].map(([label, value, color]) => (
              <div key={label} className="rounded-2xl border border-slate-800 bg-slate-950/50 p-3">
                <dt className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</dt>
                <dd className={`mt-1 font-mono text-lg font-bold ${color}`}>{value}</dd>
              </div>
            ))}
          </dl>
        </Card>
      </div>

      {summary.topContributors?.length > 0 && (
        <Card title="What drives this score" icon={Info}>
          <ul className="space-y-2">
            {summary.topContributors.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-3 text-sm">
                <button type="button" onClick={() => { setSeverityFilter('all'); setVerificationFilter('all'); setOpenId(c.id); document.getElementById(`finding-${c.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }); }} className="min-w-0 truncate text-left text-slate-300 hover:text-cyan-200">
                  {c.title}
                </button>
                <span className="shrink-0 font-mono text-xs text-slate-500">{c.points} pts</span>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-[11px] leading-relaxed text-slate-500">{summary.methodology}</p>
        </Card>
      )}

      {/* Findings */}
      <Card title={`Findings (${filtered.length} of ${findings.length})`} icon={AlertTriangle}>
        <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by severity">
            {['all', ...SEVERITY_ORDER].map((s) => (
              <button key={s} type="button" onClick={() => setSeverityFilter(s)} aria-pressed={severityFilter === s}
                className={`rounded-full border px-3 py-1 text-xs font-semibold transition ${severityFilter === s ? 'border-cyan-500/60 bg-cyan-500/15 text-cyan-200' : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}>
                {s === 'all' ? 'All severities' : `${SEVERITY[s].label} (${summary.bySeverity?.[s] ?? 0})`}
              </button>
            ))}
          </div>
          <select value={verificationFilter} onChange={(e) => setVerificationFilter(e.target.value)} aria-label="Filter by verification status"
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 outline-none focus:border-cyan-500">
            <option value="all">All verification states</option>
            {Object.entries(VERIFICATION).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
        </div>
        {filtered.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
            {findings.length ? 'No findings match the selected filters.' : 'No findings were reported by the executed checks.'}
          </p>
        ) : (
          <div className="space-y-3">
            {filtered.map((f) => (
              <div key={f.id} id={`finding-${f.id}`}>
                <FindingCard finding={f} open={openId === f.id} onToggle={() => setOpenId(openId === f.id ? null : f.id)} />
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Remediation */}
      {remediation.length > 0 && (
        <Card title="Recommended next steps" icon={CheckCircle2}>
          <ol className="space-y-3">
            {remediation.map((f, i) => (
              <li key={f.id} className="flex gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold text-slate-900" style={{ background: SEVERITY[f.severity].color }}>{i + 1}</span>
                <span className="min-w-0 text-sm">
                  <span className="block font-semibold text-slate-200">{f.title}</span>
                  <span className="block text-slate-400">{f.remediation}</span>
                </span>
              </li>
            ))}
          </ol>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* TLS */}
        <Card title="TLS configuration" icon={Lock}>
          {!tls ? (
            <p className="text-sm text-slate-500">TLS was not analysed (HTTPS not available or the check was skipped).</p>
          ) : (
            <div className="space-y-4 text-sm">
              <div className="flex flex-wrap gap-2">
                {Object.entries(tls.supportedProtocols || {}).map(([proto, state]) => {
                  const legacy = proto === 'TLSv1' || proto === 'TLSv1.1';
                  const tone = state !== 'supported' ? 'border-slate-700 text-slate-500' : legacy ? 'border-orange-500/40 bg-orange-500/10 text-orange-200' : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200';
                  return <span key={proto} className={`rounded-lg border px-2.5 py-1 font-mono text-xs ${tone}`}>{proto}: {state}</span>;
                })}
              </div>
              {cert && (
                <dl className="grid gap-2 sm:grid-cols-[140px_1fr]">
                  {[
                    ['Negotiated', `${tls.negotiatedProtocol} · ${tls.cipher}`],
                    ['Subject', cert.subject],
                    ['Issuer', cert.issuer],
                    ['Valid until', `${cert.validTo ? new Date(cert.validTo).toLocaleDateString() : '—'} (${cert.daysRemaining} days)`],
                    ['Chain', cert.trusted ? 'Trusted' : `Not trusted — ${cert.trustError}`],
                    ['Hostname match', cert.hostnameMatches ? 'Yes' : 'No'],
                  ].map(([k, v]) => (
                    <React.Fragment key={k}>
                      <dt className="text-xs font-semibold text-slate-500">{k}</dt>
                      <dd className="break-all text-slate-200">{v || '—'}</dd>
                    </React.Fragment>
                  ))}
                </dl>
              )}
            </div>
          )}
        </Card>

        {/* Technologies */}
        <Card title="Detected technologies" icon={Cpu}>
          {!scan.technologies?.length ? (
            <p className="text-sm text-slate-500">No technologies identified{scan.profile === 'quick' ? ' (fingerprinting runs in Standard and Comprehensive profiles)' : ''}.</p>
          ) : (
            <ul className="space-y-2">
              {scan.technologies.map((t) => (
                <li key={t.name} className="rounded-xl border border-slate-800 bg-slate-950/50 px-3 py-2">
                  <span className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-200">{t.name} {t.version && <span className="font-mono text-cyan-300">{t.version}</span>}</span>
                    <span className="text-[11px] text-slate-500">{t.category} · {t.confidence} confidence</span>
                  </span>
                  <span className="mt-0.5 block break-all font-mono text-[11px] text-slate-500">{t.evidence}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {/* Headers */}
      {headerRows.length > 0 && (
        <Card title={`HTTP security configuration (${scan.headerSnapshot.status} · ${scan.headerSnapshot.url})`} icon={ShieldCheck}>
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full min-w-[520px] text-left text-xs">
              <tbody>
                {headerRows.map(([name, value]) => (
                  <tr key={name} className="border-b border-slate-800 last:border-0 align-top">
                    <th className="w-60 px-3 py-2 font-mono font-semibold text-slate-400">{name}</th>
                    <td className={`break-all px-3 py-2 font-mono ${value ? 'text-slate-200' : 'text-slate-600'}`}>{value || 'not set'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Checks + limitations */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Checks executed" icon={ListChecks}>
          <ul className="space-y-2">
            {(scan.checks || []).map((c) => (
              <li key={c.id} className="flex items-start gap-3">
                <span className="mt-0.5"><CheckIcon status={c.status} /></span>
                <span className="min-w-0 flex-1 text-sm">
                  <span className="block text-slate-200">{c.label} <span className={`text-xs ${STATUS_STYLE[c.status]?.className}`}>· {STATUS_STYLE[c.status]?.label}</span></span>
                  {c.note && <span className="block break-words text-xs text-slate-500">{c.note}</span>}
                </span>
                <span className="shrink-0 font-mono text-[11px] text-slate-600">{formatDuration(c.durationMs)}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Assessment limitations" icon={Info}>
          <ul className="list-disc space-y-2 pl-5 text-sm text-slate-400">
            {(scan.limitations || []).map((l) => <li key={l}>{l}</li>)}
          </ul>
        </Card>
      </div>
    </div>
  );
};

export default ScanReport;
