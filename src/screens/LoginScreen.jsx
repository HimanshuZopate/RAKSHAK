import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AlertCircle, Eye, EyeOff, Lock, Mail, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const LoginScreen = () => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleChange = (event) => {
    setFormData({ ...formData, [event.target.name]: event.target.value });
    setErrorMessage('');
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    setErrorMessage('');
    if (!formData.email.trim() || !formData.password) {
      setErrorMessage('Please enter both email and password.');
      return;
    }

    setIsSubmitting(true);
    const result = await login(formData.email.trim(), formData.password);
    setIsSubmitting(false);
    if (result.success) {
      navigate(location.state?.from?.pathname || '/dashboard', { replace: true });
    } else {
      setErrorMessage(result.error);
    }
  };

  return (
    <main className="auth-screen">
      <div className="auth-orb auth-orb-one" />
      <div className="auth-orb auth-orb-two" />
      <section className="auth-card">
        <div className="auth-icon"><ShieldCheck size={30} /></div>
        <p className="auth-kicker">RAKSHAK SECURITY</p>
        <h1>Welcome back</h1>
        <p className="auth-subtitle">Sign in to continue protecting your digital world.</p>

        {errorMessage && (
          <div className="auth-alert">
            <AlertCircle size={18} />
            <div>
              <strong>{errorMessage}</strong>
            </div>
          </div>
        )}

        <form onSubmit={handleLogin} className="auth-form">
          <label>Email address
            <span className="auth-input"><Mail size={17} /><input name="email" type="email" value={formData.email} onChange={handleChange} placeholder="you@example.com" required /></span>
          </label>
          <label>Password
            <Link to="/reset">Forgot password?</Link>
            <span className="auth-input"><Lock size={17} /><input name="password" type={showPassword ? 'text' : 'password'} value={formData.password} onChange={handleChange} placeholder="Enter your password" required /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></span>
          </label>
          <button className="auth-submit" type="submit" disabled={isSubmitting}>{isSubmitting ? 'Signing in...' : 'Sign in'}</button>
        </form>
        <p className="auth-footer">New to Rakshak? <Link to="/signup">Create an account</Link></p>
      </section>
    </main>
  );
};

export default LoginScreen;
