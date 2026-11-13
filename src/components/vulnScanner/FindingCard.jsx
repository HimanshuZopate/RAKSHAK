import React from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { ChevronDown, ExternalLink } from 'lucide-react';
import { CONFIDENCE_LABEL, SEVERITY, VERIFICATION } from './constants';

const Section = ({ title, children }) => (
  <div>
    <h4 className="mb-1.5 text-[11px] font-bold uppercase tracking-wider text-slate-500">{title}</h4>
    <div className="text-sm leading-relaxed text-slate-300">{children}</div>
  </div>
);

const FindingCard = ({ finding, open, onToggle }) => {
  const reduceMotion = useReducedMotion();
  const sev = SEVERITY[finding.severity] || SEVERITY.info;
  const ver = VERIFICATION[finding.verification] || VERIFICATION.informational;

  return (
    <motion.article
      layout={!reduceMotion}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60"
      style={{ borderLeft: `3px solid ${sev.color}` }}
    >
      <button type="button" onClick={onToggle} aria-expanded={open} className="flex w-full items-start gap-3 p-4 text-left transition hover:bg-slate-800/40 sm:items-center sm:p-5">
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className={`rounded-md border px-2 py-0.5 text-[11px] font-bold uppercase ${sev.badge}`}>{sev.label}</span>
            <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${ver.badge}`} title={ver.hint}>{ver.label}</span>
            <span className="text-[11px] text-slate-500">{CONFIDENCE_LABEL[finding.confidence]}</span>
          </span>
          <span className="mt-2 block break-words text-sm font-semibold text-white sm:text-base">{finding.title}</span>
          <span className="mt-0.5 block text-xs text-slate-500">{finding.category}{finding.owasp ? ` · ${finding.owasp}` : ''}</span>
        </span>
        <ChevronDown className={`mt-1 h-5 w-5 shrink-0 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.25 }}
          >
            <div className="space-y-5 border-t border-slate-800 p-4 sm:p-5">
              <Section title="Description">{finding.description}</Section>
              <Section title="Affected resource"><code className="break-all font-mono text-xs text-cyan-200">{finding.affected}</code></Section>

              {finding.evidence?.length > 0 && (
                <Section title="Evidence">
                  <dl className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/70">
                    {finding.evidence.map((e, i) => (
                      <div key={i} className="grid gap-1 border-b border-slate-800/80 px-3 py-2 last:border-0 sm:grid-cols-[200px_1fr] sm:gap-3">
                        <dt className="text-xs font-semibold text-slate-500">{e.label}</dt>
                        <dd className="break-all font-mono text-xs text-slate-200">{e.value}</dd>
                      </div>
                    ))}
                  </dl>
                </Section>
              )}

              {finding.cves?.length > 0 && (
                <Section title={`Known CVEs (top ${finding.cves.length} by CVSS)`}>
                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full min-w-[520px] text-left text-xs">
                      <thead className="bg-slate-950/80 text-slate-500">
                        <tr><th className="px-3 py-2">CVE</th><th className="px-3 py-2">CVSS</th><th className="px-3 py-2">Description</th></tr>
                      </thead>
                      <tbody>
                        {finding.cves.map((cve) => (
                          <tr key={cve.id} className="border-t border-slate-800 align-top">
                            <td className="whitespace-nowrap px-3 py-2">
                              <a href={cve.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-cyan-300 hover:underline">
                                {cve.id} <ExternalLink className="h-3 w-3" />
                              </a>
                            </td>
                            <td className="whitespace-nowrap px-3 py-2 font-mono text-slate-200">{cve.cvss ?? '—'} <span className="text-slate-500">{cve.severity || ''}</span></td>
                            <td className="px-3 py-2 text-slate-400">{cve.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              <div className="grid gap-5 md:grid-cols-2">
                <Section title="Potential impact">{finding.impact}</Section>
                <Section title="Recommended remediation">{finding.remediation}</Section>
              </div>
              <Section title="Detection method">{finding.detection}</Section>

              {finding.references?.length > 0 && (
                <Section title="References">
                  <ul className="flex flex-wrap gap-2">
                    {finding.references.map((ref) => (
                      <li key={ref.url}>
                        <a href={ref.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-cyan-500/50 hover:text-cyan-200">
                          {ref.title} <ExternalLink className="h-3 w-3" />
                        </a>
                      </li>
                    ))}
                  </ul>
                </Section>
              )}
              <p className="font-mono text-[11px] text-slate-600">Finding ID {finding.id} · first detected {new Date(finding.firstDetected).toLocaleString()}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.article>
  );
};

export default FindingCard;
