import React, { useEffect, useState, useCallback } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck, CheckCircle2, AlertTriangle, ArrowRight } from 'lucide-react';

const VerifyEmailScreen = () => {
  const [token, setToken] = useState('');
  const [status, setStatus] = useState('idle'); // 'idle' | 'verifying' | 'success' | 'error'
  const [message, setMessage] = useState('');
  const [resendEmail, setResendEmail] = useState('');
  const [resendStatus, setResendStatus] = useState('');

  const location = useLocation();
  const navigate = useNavigate();
  const { verifyEmail, resendVerification } = useAuth();

  const handleVerification = useCallback(async (verifyTokenValue) => {
    setStatus('verifying');
    setMessage('Verifying your email token with the security server...');

    const res = await verifyEmail(verifyTokenValue);
    if (res.success) {
      setStatus('success');
      setMessage(res.message);
    } else {
      setStatus('error');
      setMessage(res.error);
    }
  }, [verifyEmail]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const tokenParam = params.get('token');

    if (tokenParam) {
      setToken(tokenParam);
      handleVerification(tokenParam);
    }
  }, [location.search, handleVerification]);

  const handleManualSubmit = (e) => {
    e.preventDefault();
    if (!token.trim()) return;
    handleVerification(token.trim());
  };

  const handleResend = async (e) => {
    e.preventDefault();
    if (!resendEmail.trim()) return;
    setResendStatus('sending');
    const res = await resendVerification(resendEmail.trim());
    if (res.success) {
      setResendStatus('sent');
    } else {
      setResendStatus('error');
    }
  };

  return (
    <div className="hero min-h-screen bg-slate-50 flex items-center justify-center px-4">
      <div className="card w-full max-w-md bg-white border border-slate-100 shadow-2xl rounded-3xl overflow-hidden">
        <div className="card-body p-8 text-center">
          {/* Header Icon */}
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-3xl bg-blue-50 text-blue-600 mb-4 mx-auto shadow-inner">
            <ShieldCheck className="w-8 h-8" />
          </div>

          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Account Email Verification
          </h1>

          {/* Verifying State */}
          {status === 'verifying' && (
            <div className="py-8 space-y-4">
              <span className="loading loading-spinner loading-lg text-blue-600"></span>
              <p className="text-slate-600 text-sm font-medium">{message}</p>
            </div>
          )}

          {/* Success State */}
          {status === 'success' && (
            <div className="py-6 space-y-4">
              <div className="w-14 h-14 bg-emerald-50 text-emerald-600 rounded-2xl flex items-center justify-center mx-auto shadow-sm">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800">Verification Successful</h3>
                <p className="text-slate-500 text-sm mt-1">{message}</p>
              </div>
              <button
                onClick={() => navigate('/dashboard')}
                className="btn btn-primary w-full rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold normal-case flex items-center justify-center gap-2 mt-4 shadow-lg shadow-blue-500/20"
              >
                Access Dashboard <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Error State */}
          {status === 'error' && (
            <div className="py-4 space-y-4 text-left">
              <div className="p-4 rounded-2xl bg-amber-50 border border-amber-200 text-amber-800 text-sm flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-600 mt-0.5" />
                <div>
                  <p className="font-semibold">Verification Failed</p>
                  <p className="text-xs text-amber-700 mt-0.5">{message}</p>
                </div>
              </div>

              {/* Resend Form */}
              <form onSubmit={handleResend} className="space-y-3 pt-2">
                <label className="label py-0">
                  <span className="label-text text-xs font-semibold text-slate-600">
                    Request a new verification link:
                  </span>
                </label>
                <input
                  type="email"
                  value={resendEmail}
                  onChange={(e) => setResendEmail(e.target.value)}
                  placeholder="Enter your registration email"
                  className="input input-bordered w-full rounded-xl bg-slate-50 text-sm"
                  required
                />
                <button
                  type="submit"
                  disabled={resendStatus === 'sending'}
                  className="btn btn-outline w-full rounded-xl text-slate-700 border-slate-300 hover:bg-slate-50 normal-case text-sm"
                >
                  {resendStatus === 'sending' ? (
                    'Dispatching...'
                  ) : resendStatus === 'sent' ? (
                    'Link Sent! Check your inbox'
                  ) : (
                    'Resend Verification Email'
                  )}
                </button>
              </form>

              <div className="pt-2 text-center">
                <Link to="/" className="text-xs text-blue-600 font-semibold hover:underline">
                  Back to Sign In
                </Link>
              </div>
            </div>
          )}

          {/* Idle State (Manual Token Entry) */}
          {status === 'idle' && (
            <form onSubmit={handleManualSubmit} className="py-4 space-y-4 text-left">
              <p className="text-slate-500 text-xs text-center">
                Paste the verification token provided in your verification email below:
              </p>
              <div className="form-control">
                <input
                  type="text"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="Paste verification token here"
                  className="input input-bordered w-full rounded-xl bg-slate-50 text-sm font-mono"
                  required
                />
              </div>
              <button
                type="submit"
                className="btn btn-primary w-full rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold normal-case"
              >
                Verify Token
              </button>
              <div className="text-center pt-2">
                <Link to="/" className="text-xs text-slate-500 hover:text-slate-800">
                  Return to Login
                </Link>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default VerifyEmailScreen;
