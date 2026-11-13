import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Radar } from 'lucide-react';
import VulnerabilityScanner from '../components/VulnerabilityScanner';

const VulnerabilitiesScreen = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-950 text-left text-slate-200">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_20%_0%,rgba(34,211,238,0.08),transparent_40%),radial-gradient(circle_at_90%_10%,rgba(59,130,246,0.08),transparent_35%)]" aria-hidden="true" />
      <div className="relative mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:py-10">
        <header className="mb-6 flex items-center justify-between gap-4 border-b border-slate-800 pb-5">
          <button
            type="button"
            onClick={() => navigate('/dashboard')}
            className="inline-flex items-center gap-2 text-sm font-medium text-slate-400 transition hover:text-white"
          >
            <ArrowLeft className="h-4 w-4" /> Back to Dashboard
          </button>
          <span className="inline-flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-400">
            <Radar className="h-3.5 w-3.5 text-cyan-400" /> Evidence-based web assessment
          </span>
        </header>
        <VulnerabilityScanner />
      </div>
    </div>
  );
};

export default VulnerabilitiesScreen;
