import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, ShieldAlert } from 'lucide-react';
import VulnerabilityScanner from '../components/VulnerabilityScanner';

const VulnerabilitiesScreen = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 p-4 md:p-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <button
          onClick={() => navigate('/dashboard')}
          className="p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
        >
          <ArrowLeft className="w-5 h-5 text-slate-600 dark:text-slate-400" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-primary" />
            Vulnerability Scanner
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm">
            Scan and identify vulnerabilities in your assets using real-time NVD CVE API data.
          </p>
        </div>
      </div>

      <VulnerabilityScanner />
    </div>
  );
};

export default VulnerabilitiesScreen;
