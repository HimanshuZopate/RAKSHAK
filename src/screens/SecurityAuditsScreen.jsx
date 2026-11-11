import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  Search,
  RefreshCcw,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  CalendarRange,
  ChevronLeft,
  ChevronRight,
  Eye,
  Filter,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';

const emptySummary = {
  total: 0,
  success: 0,
  failure: 0,
  denied: 0,
  highSeverity: 0,
  period: { start: null, end: null },
};

const defaultFilters = {
  category: '',
  action: '',
  status: '',
  severity: '',
  actor: '',
  startDate: '',
  endDate: '',
  search: '',
};

const getSeverityClasses = (severity = 'informational') => {
  const map = {
    informational: 'bg-slate-700 text-slate-200',
    low: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30',
    medium: 'bg-amber-500/20 text-amber-300 border border-amber-500/30',
    high: 'bg-orange-500/20 text-orange-300 border border-orange-500/30',
    critical: 'bg-red-500/20 text-red-300 border border-red-500/30',
  };
  return map[severity] || map.informational;
};

const getStatusClasses = (status = 'success') => {
  const map = {
    success: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30',
    failure: 'bg-red-500/20 text-red-300 border border-red-500/30',
    denied: 'bg-amber-500/20 text-amber-300 border border-amber-500/30',
    partial: 'bg-sky-500/20 text-sky-300 border border-sky-500/30',
  };
  return map[status] || map.success;
};

const formatDate = (value) => {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  }).format(date);
};

const summarizeMetadata = (metadata) => {
  if (!metadata || typeof metadata !== 'object') return '—';
  const keys = Object.keys(metadata).slice(0, 4);
  if (!keys.length) return 'No extra metadata';
  return keys
    .map((key) => `${key}: ${typeof metadata[key] === 'object' ? JSON.stringify(metadata[key]).slice(0, 36) : String(metadata[key])}`)
    .join(' | ')
    .slice(0, 120);
};

const SecurityAuditsScreen = () => {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [summary, setSummary] = useState(emptySummary);
  const [pagination, setPagination] = useState({ page: 1, limit: 10, totalPages: 1, totalItems: 0 });
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [filters, setFilters] = useState(defaultFilters);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchAudits = async (page = 1, queryFilters = filters) => {
    try {
      setLoading(true);
      setError('');
      const params = {
        ...queryFilters,
        page,
        limit: pagination.limit || 10,
      };
      const response = await api.get('/audits', { params });
      setEvents(response.data.events || []);
      setSummary(response.data.summary || emptySummary);
      setPagination(response.data.pagination || { page, limit: 10, totalPages: 1, totalItems: 0 });
    } catch (err) {
      console.error('Failed to load audit logs:', err);
      setEvents([]);
      setSummary(emptySummary);
      setError(err.response?.data?.error || 'Unable to load audit records right now.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudits(1, filters);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const applyFilters = () => {
    fetchAudits(1, filters);
  };

  const resetFilters = () => {
    const cleared = { ...defaultFilters };
    setFilters(cleared);
    fetchAudits(1, cleared);
  };

  const metricCards = useMemo(
    () => [
      {
        label: 'Total Events',
        value: summary.total,
        icon: ShieldAlert,
        tone: 'bg-sky-500/10 text-sky-300',
      },
      {
        label: 'Successful',
        value: summary.success,
        icon: CheckCircle2,
        tone: 'bg-emerald-500/10 text-emerald-300',
      },
      {
        label: 'Failed',
        value: summary.failure,
        icon: XCircle,
        tone: 'bg-red-500/10 text-red-300',
      },
      {
        label: 'Denied',
        value: summary.denied,
        icon: AlertTriangle,
        tone: 'bg-amber-500/10 text-amber-300',
      },
      {
        label: 'High Severity',
        value: summary.highSeverity,
        icon: ShieldAlert,
        tone: 'bg-orange-500/10 text-orange-300',
      },
    ],
    [summary]
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 md:p-8">
      <div className="mx-auto max-w-7xl">
        <header className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/dashboard')}
              className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-slate-200 transition hover:bg-slate-800"
            >
              <ArrowLeft className="h-5 w-5" />
            </button>
            <div>
              <p className="text-xs uppercase tracking-[0.24em] text-cyan-300">Security Operations</p>
              <h1 className="text-2xl font-bold md:text-3xl">Application Audit Logs</h1>
            </div>
          </div>
        </header>

        <div className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          {metricCards.map(({ label, value, icon: Icon, tone }) => (
            <div key={label} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4 shadow-lg shadow-slate-950/40">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400">{label}</span>
                <span className={`rounded-lg p-2 ${tone}`}>
                  <Icon className="h-4 w-4" />
                </span>
              </div>
              <div className="mt-4 text-3xl font-bold">{value}</div>
            </div>
          ))}
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4 shadow-xl shadow-slate-950/40">
          <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:flex-wrap lg:items-end">
            <label className="flex flex-1 min-w-[160px] flex-col gap-1 text-sm text-slate-300">
              Search
              <div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2">
                <Search className="h-4 w-4 text-slate-400" />
                <input
                  value={filters.search}
                  onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
                  onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                  placeholder="event id, action, source"
                  className="w-full bg-transparent text-sm outline-none placeholder:text-slate-500"
                />
              </div>
            </label>

            <label className="flex min-w-[140px] flex-col gap-1 text-sm text-slate-300">
              Category
              <select
                value={filters.category}
                onChange={(e) => setFilters((prev) => ({ ...prev, category: e.target.value }))}
                className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none"
              >
                <option value="">Any</option>
                <option value="authentication">Authentication</option>
                <option value="security scan">Security Scan</option>
                <option value="phishing">Phishing</option>
                <option value="simulation">Simulation</option>
                <option value="administration">Administration</option>
                <option value="system">System</option>
              </select>
            </label>

            <label className="flex min-w-[120px] flex-col gap-1 text-sm text-slate-300">
              Status
              <select
                value={filters.status}
                onChange={(e) => setFilters((prev) => ({ ...prev, status: e.target.value }))}
                className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none"
              >
                <option value="">Any</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="denied">Denied</option>
                <option value="partial">Partial</option>
              </select>
            </label>

            <label className="flex min-w-[120px] flex-col gap-1 text-sm text-slate-300">
              Severity
              <select
                value={filters.severity}
                onChange={(e) => setFilters((prev) => ({ ...prev, severity: e.target.value }))}
                className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none"
              >
                <option value="">Any</option>
                <option value="informational">Informational</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>

            <div className="flex items-center gap-2">
              <button
                onClick={applyFilters}
                className="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 transition hover:bg-cyan-400"
              >
                <Filter className="h-4 w-4" />
                Apply Filters
              </button>
              <button
                onClick={resetFilters}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-slate-800"
              >
                <RefreshCcw className="h-4 w-4" />
                Reset
              </button>
            </div>
          </div>

          <div className="mb-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <label className="flex flex-col gap-1 text-sm text-slate-300">
              From
              <div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2">
                <CalendarRange className="h-4 w-4 text-slate-400" />
                <input
                  type="date"
                  value={filters.startDate}
                  onChange={(e) => setFilters((prev) => ({ ...prev, startDate: e.target.value }))}
                  className="w-full bg-transparent text-sm outline-none"
                />
              </div>
            </label>
            <label className="flex flex-col gap-1 text-sm text-slate-300">
              To
              <div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 px-3 py-2">
                <CalendarRange className="h-4 w-4 text-slate-400" />
                <input
                  type="date"
                  value={filters.endDate}
                  onChange={(e) => setFilters((prev) => ({ ...prev, endDate: e.target.value }))}
                  className="w-full bg-transparent text-sm outline-none"
                />
              </div>
            </label>
          </div>

          {error && (
            <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="min-w-full border-separate border-spacing-y-2 text-left text-sm">
              <thead>
                <tr className="text-slate-400">
                  <th className="px-3 py-2 font-medium">Timestamp</th>
                  <th className="px-3 py-2 font-medium">Actor</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                  <th className="px-3 py-2 font-medium">Category</th>
                  <th className="px-3 py-2 font-medium">Resource</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="8" className="px-3 py-8 text-center text-slate-400">
                      Loading audit events...
                    </td>
                  </tr>
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="px-3 py-8 text-center text-slate-400">
                      No audit records match the current filters. Supported actions will appear here once they are performed.
                    </td>
                  </tr>
                ) : (
                  events.map((event) => (
                    <tr
                      key={event.eventId || event.id || event._id}
                      onClick={() => setSelectedEvent(event)}
                      className="cursor-pointer rounded-xl border border-slate-800 bg-slate-950/70 transition hover:border-cyan-500/50 hover:bg-slate-900"
                    >
                      <td className="rounded-l-xl px-3 py-3 text-slate-200">{formatDate(event.timestamp)}</td>
                      <td className="px-3 py-3 text-slate-300">
                        <div className="font-medium">{event.actorType || 'system'}</div>
                        <div className="text-xs text-slate-500">{event.actorId || 'system'}</div>
                      </td>
                      <td className="px-3 py-3 text-slate-200">{event.action}</td>
                      <td className="px-3 py-3 text-slate-300">{event.category}</td>
                      <td className="px-3 py-3 text-slate-300">{event.resourceType || 'application'}</td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium capitalize ${getStatusClasses(event.status)}`}>
                          {event.status}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium capitalize ${getSeverityClasses(event.severity)}`}>
                          {event.severity || 'informational'}
                        </span>
                      </td>
                      <td className="rounded-r-xl px-3 py-3 text-slate-400">{summarizeMetadata(event.metadata)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-5 flex flex-col gap-3 border-t border-slate-800 pt-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-slate-400">
              Showing {events.length} of {pagination.totalItems} records
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => fetchAudits(Math.max(1, pagination.page - 1), filters)}
                disabled={pagination.page <= 1}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" />
                Previous
              </button>
              <span className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
                Page {pagination.page} of {pagination.totalPages}
              </span>
              <button
                onClick={() => fetchAudits(Math.min(pagination.totalPages, pagination.page + 1), filters)}
                disabled={pagination.page >= pagination.totalPages}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
          <div className="max-h-[80vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl shadow-slate-950/80">
            <div className="mb-5 flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">Event Details</p>
                <h2 className="mt-1 text-xl font-bold">{selectedEvent.action}</h2>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
              >
                Close
              </button>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Event ID</div>
                <div className="mt-1 break-all text-sm text-slate-200">{selectedEvent.eventId || selectedEvent.id}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Timestamp</div>
                <div className="mt-1 text-sm text-slate-200">{formatDate(selectedEvent.timestamp)}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Actor</div>
                <div className="mt-1 text-sm text-slate-200">{selectedEvent.actorType || 'system'} ({selectedEvent.actorId || 'system'})</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Outcome</div>
                <div className="mt-1 text-sm text-slate-200">
                  <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium capitalize ${getStatusClasses(selectedEvent.status)}`}>
                    {selectedEvent.status}
                  </span>
                </div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Category</div>
                <div className="mt-1 text-sm text-slate-200">{selectedEvent.category}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Source</div>
                <div className="mt-1 text-sm text-slate-200">{selectedEvent.source}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Resource</div>
                <div className="mt-1 text-sm text-slate-200">{selectedEvent.resourceType || 'application'}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Request ID</div>
                <div className="mt-1 break-all text-sm text-slate-200">{selectedEvent.requestId || '—'}</div>
              </div>
            </div>

            <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-slate-500">
                <Eye className="h-4 w-4" />
                Sanitized Metadata
              </div>
              <pre className="overflow-auto whitespace-pre-wrap break-words text-xs text-slate-300">
                {JSON.stringify(selectedEvent.metadata || {}, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityAuditsScreen;
