// Shared presentation constants for the vulnerability scanner UI.

export const SEVERITY = {
  critical: { label: 'Critical', color: '#ef4444', text: 'text-red-300', badge: 'bg-red-500/15 text-red-300 border-red-500/30', dot: 'bg-red-500' },
  high: { label: 'High', color: '#f97316', text: 'text-orange-300', badge: 'bg-orange-500/15 text-orange-300 border-orange-500/30', dot: 'bg-orange-500' },
  medium: { label: 'Medium', color: '#eab308', text: 'text-yellow-300', badge: 'bg-yellow-500/15 text-yellow-200 border-yellow-500/30', dot: 'bg-yellow-400' },
  low: { label: 'Low', color: '#3b82f6', text: 'text-blue-300', badge: 'bg-blue-500/15 text-blue-300 border-blue-500/30', dot: 'bg-blue-500' },
  info: { label: 'Info', color: '#64748b', text: 'text-slate-300', badge: 'bg-slate-500/15 text-slate-300 border-slate-500/30', dot: 'bg-slate-500' },
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const VERIFICATION = {
  confirmed: { label: 'Confirmed', badge: 'bg-rose-500/10 text-rose-200 border-rose-400/30', hint: 'Demonstrated directly by a probe.' },
  misconfiguration: { label: 'Misconfiguration', badge: 'bg-amber-500/10 text-amber-200 border-amber-400/30', hint: 'Configuration observed directly in the responses.' },
  potential: { label: 'Potential', badge: 'bg-violet-500/10 text-violet-200 border-violet-400/30', hint: 'Indicator that needs manual verification.' },
  informational: { label: 'Informational', badge: 'bg-slate-500/10 text-slate-300 border-slate-500/30', hint: 'Observation without direct risk.' },
  inconclusive: { label: 'Inconclusive', badge: 'bg-slate-500/10 text-slate-400 border-slate-500/30', hint: 'No reliable verdict could be reached.' },
};

export const CONFIDENCE_LABEL = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' };

export const RISK_LEVEL = {
  critical: { label: 'Critical risk', color: '#ef4444', ring: 'from-red-500 to-rose-600' },
  high: { label: 'High risk', color: '#f97316', ring: 'from-orange-500 to-red-500' },
  medium: { label: 'Medium risk', color: '#eab308', ring: 'from-yellow-400 to-orange-500' },
  low: { label: 'Low risk', color: '#3b82f6', ring: 'from-sky-400 to-blue-600' },
  minimal: { label: 'Minimal risk', color: '#10b981', ring: 'from-emerald-400 to-teal-500' },
};

export const PROFILES = [
  {
    id: 'quick',
    name: 'Quick Assessment',
    intensity: 'Passive · ~10 requests',
    description: 'Connectivity, HTTPS enforcement, security headers, TLS certificate & protocol versions, cookies and CORS.',
  },
  {
    id: 'standard',
    name: 'Standard Assessment',
    intensity: 'Safe active probes · ~30 requests',
    description: 'Everything in Quick plus HTTP methods, information disclosure, exposed files, mixed content, technology detection and safe XSS / SQL injection / open-redirect indicators.',
    recommended: true,
  },
  {
    id: 'comprehensive',
    name: 'Comprehensive Assessment',
    intensity: 'Extended · ~50 requests + NVD',
    description: 'Everything in Standard plus an extended exposed-path list, source-map discovery, common redirect parameters and CVE correlation with the NIST National Vulnerability Database.',
  },
];

export const STATUS_STYLE = {
  passed: { label: 'Passed', className: 'text-emerald-300' },
  issues: { label: 'Issues found', className: 'text-amber-300' },
  inconclusive: { label: 'Inconclusive', className: 'text-slate-300' },
  skipped: { label: 'Skipped', className: 'text-slate-500' },
  error: { label: 'Error', className: 'text-rose-300' },
  cancelled: { label: 'Cancelled', className: 'text-slate-500' },
  running: { label: 'Running', className: 'text-cyan-300' },
  pending: { label: 'Pending', className: 'text-slate-600' },
};

export const SCAN_STATUS_LABEL = {
  running: 'Running',
  completed: 'Completed',
  cancelled: 'Cancelled',
  failed: 'Failed',
  timed_out: 'Timed out',
};

export const formatDuration = (ms) => {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms} ms`;
  const s = Math.round(ms / 100) / 10;
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
};

export const formatDate = (value) => (value ? new Date(value).toLocaleString() : '—');
