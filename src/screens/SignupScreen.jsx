import React, { useState } from 'react';
import { CheckCircle2, Eye, EyeOff, Lock, Mail, ShieldCheck } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const SignupScreen = () => {
  const [formData, setFormData] = useState({ email: '', password: '', confirmPassword: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const { register } = useAuth();
  const navigate = useNavigate();
  const criteria = {
    length: formData.password.length >= 8,
    uppercase: /[A-Z]/.test(formData.password),
    lowercase: /[a-z]/.test(formData.password),
    number: /[0-9]/.test(formData.password),
    special: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(formData.password),
  };

  const handleChange = (event) => {
    setFormData({ ...formData, [event.target.name]: event.target.value });
    setErrorMessage('');
  };

  const handleSignup = async (event) => {
    event.preventDefault();
    setErrorMessage('');
    if (!formData.email.trim() || !formData.password) return setErrorMessage('Please fill in all required fields.');
    if (formData.password !== formData.confirmPassword) return setErrorMessage('Passwords do not match.');
    if (Object.values(criteria).some((valid) => !valid)) return setErrorMessage('Please satisfy all password security requirements.');
    setIsSubmitting(true);
    const result = await register(formData.email.trim(), formData.password);
    setIsSubmitting(false);
    if (result.success) navigate('/dashboard', { replace: true });
    else setErrorMessage(result.error);
  };

  return (
    <main className="auth-screen">
      <div className="auth-orb auth-orb-one" /><div className="auth-orb auth-orb-two" />
      <section className="auth-card">
        <div className="auth-icon"><ShieldCheck size={30} /></div>
        <p className="auth-kicker">RAKSHAK SECURITY</p><h1>Create your account</h1>
        <p className="auth-subtitle">Start building safer digital habits with Rakshak.</p>
        {errorMessage && <div className="auth-alert"><Lock size={18} /><strong>{errorMessage}</strong></div>}
        <form onSubmit={handleSignup} className="auth-form">
          <label>Email address<span className="auth-input"><Mail size={17} /><input name="email" type="email" value={formData.email} onChange={handleChange} placeholder="you@example.com" required /></span></label>
          <label>Password<span className="auth-input"><Lock size={17} /><input name="password" type={showPassword ? 'text' : 'password'} value={formData.password} onChange={handleChange} placeholder="Create a strong password" required /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></span></label>
          <label>Confirm password<span className="auth-input"><Lock size={17} /><input name="confirmPassword" type="password" value={formData.confirmPassword} onChange={handleChange} placeholder="Repeat your password" required /></span></label>
          <div className="auth-requirements">{Object.entries(criteria).map(([name, valid]) => <span className={valid ? 'valid' : ''} key={name}><CheckCircle2 size={13} /> {name}</span>)}</div>
          <button className="auth-submit" type="submit" disabled={isSubmitting}>{isSubmitting ? 'Creating account...' : 'Create account'}</button>
        </form>
        <p className="auth-footer">Already have an account? <Link to="/login">Sign in</Link></p>
      </section>
    </main>
  );
};

export default SignupScreen;
