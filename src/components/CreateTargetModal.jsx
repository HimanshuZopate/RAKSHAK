import React, { useState } from 'react';
import { X, Server, Plus, Loader2 } from 'lucide-react';
import api from '../utils/api';

const CreateTargetModal = ({ isOpen, onClose, onTargetCreated }) => {
  const [formData, setFormData] = useState({
    name: '',
    host: '',
    environment: 'Production',
    techStack: '' // Comma-separated
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      // Parse techStack string into array of objects { name, version }
      const parsedTechStack = formData.techStack
        .split(',')
        .map(t => t.trim())
        .filter(t => t)
        .map(t => ({ name: t, version: 'unknown' }));

      const payload = {
        name: formData.name,
        host: formData.host,
        environment: formData.environment,
        techStack: parsedTechStack
      };

      const res = await api.post('/targets', payload);
      
      if (res.data?.success) {
        onTargetCreated(res.data.target);
        // Reset form
        setFormData({ name: '', host: '', environment: 'Production', techStack: '' });
        onClose();
      }
    } catch (err) {
      console.error('Failed to create target:', err);
      setError(err.response?.data?.error || 'Failed to create target. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
      <div 
        className="bg-white dark:bg-slate-900 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden border border-slate-200 dark:border-slate-800"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-center p-5 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/10 rounded-xl flex items-center justify-center">
              <Server className="w-5 h-5 text-blue-500" />
            </div>
            <div>
              <h2 className="font-bold text-slate-800 dark:text-white text-lg">Add New Target</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Register an asset for scanning</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 flex flex-col gap-4">
          {error && (
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 text-sm p-3 rounded-xl">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Target Name
            </label>
            <input
              type="text"
              name="name"
              required
              placeholder="e.g. Production API"
              value={formData.name}
              onChange={handleChange}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:text-white transition-all"
            />
          </div>

          <div>
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Host / IP Address
            </label>
            <input
              type="text"
              name="host"
              required
              placeholder="e.g. api.example.com or 192.168.1.100"
              value={formData.host}
              onChange={handleChange}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:text-white transition-all"
            />
          </div>

          <div>
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Environment
            </label>
            <select
              name="environment"
              value={formData.environment}
              onChange={handleChange}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:text-white transition-all appearance-none cursor-pointer"
            >
              <option value="Production">Production</option>
              <option value="Staging">Staging</option>
              <option value="Dev">Dev</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              Tech Stack <span className="text-slate-400 font-normal">(comma-separated)</span>
            </label>
            <input
              type="text"
              name="techStack"
              placeholder="e.g. nginx, nodejs, react"
              value={formData.techStack}
              onChange={handleChange}
              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:text-white transition-all"
            />
          </div>

          <div className="pt-2 mt-2 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="px-5 py-2.5 text-sm font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || !formData.name || !formData.host}
              className="flex items-center gap-2 px-6 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-xl transition-colors shadow-lg shadow-blue-500/30"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4" />
                  Create Target
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CreateTargetModal;
