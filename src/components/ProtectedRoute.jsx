import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck } from 'lucide-react';

/**
 * ProtectedRoute Wrapper Component for React Router v6
 * Restricts access to authenticated users and handles smooth loading transitions.
 */
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center text-white">
        <div className="relative flex items-center justify-center">
          <div className="w-16 h-16 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin"></div>
          <ShieldCheck className="w-8 h-8 text-blue-400 absolute animate-pulse" />
        </div>
        <p className="mt-4 text-sm font-medium text-slate-400 tracking-wider uppercase">
          Verifying Security Credentials...
        </p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center px-6 text-center text-white">
        <div className="max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
          <ShieldCheck className="mx-auto h-12 w-12 text-cyan-400" />
          <h1 className="mt-5 text-2xl font-bold">Sign in to continue</h1>
          <p className="mt-3 text-slate-400">
            Please sign in or create an account to access this protected page.
          </p>
          <div className="mt-7 flex justify-center gap-3">
            <Link
              to="/login"
              state={{ from: location }}
              className="rounded-xl bg-cyan-400 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-300"
            >
              Sign in
            </Link>
            <Link
              to="/signup"
              state={{ from: location }}
              className="rounded-xl border border-slate-700 px-5 py-3 font-semibold text-slate-200 transition hover:bg-slate-800"
            >
              Sign up
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return children;
};

export default ProtectedRoute;
