import React, { useState } from 'react';
import { ArrowLeft, Camera, Mail, Save, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

const ProfileScreen = () => {
  const { user, checkAuth } = useAuth();
  const navigate = useNavigate();
  const [displayName, setDisplayName] = useState(user?.displayName || '');
  const [avatarUrl, setAvatarUrl] = useState(user?.avatarUrl || '');
  const [status, setStatus] = useState('');

  const saveProfile = async (event) => {
    event.preventDefault();
    setStatus('saving');
    try {
      await api.patch('/auth/profile', { displayName, avatarUrl });
      await checkAuth();
      setStatus('saved');
    } catch (error) {
      setStatus(error.response?.data?.error || 'Unable to save profile.');
    }
  };

  const avatar = avatarUrl || `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(user?.email || 'Rakshak')}&backgroundColor=b6e3f4`;

  return (
    <main className="profile-page">
      <div className="profile-panel">
        <button className="profile-back" onClick={() => navigate('/dashboard')}><ArrowLeft size={17} /> Dashboard</button>
        <div className="profile-heading"><div className="profile-avatar"><img src={avatar} alt="Profile avatar" /></div><div><p className="auth-kicker">RAKSHAK PROFILE</p><h1>Account details</h1><p>Manage the identity shown across your security workspace.</p></div></div>
        <form onSubmit={saveProfile} className="profile-form">
          <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="Your name" maxLength={80} /></label>
          <label>Email address<span className="profile-readonly"><Mail size={16} />{user?.email}<small>Verified account</small></span></label>
          <label>Profile photo URL<span className="profile-input"><Camera size={16} /><input value={avatarUrl} onChange={(event) => setAvatarUrl(event.target.value)} placeholder="https://example.com/avatar.png" maxLength={500} /></span></label>
          <div className="profile-details"><span><b>Role</b>{user?.role || 'user'}</span><span><b>Member since</b>{user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Recently'}</span><span><b>Security status</b><em><ShieldCheck size={14} /> Active</em></span></div>
          <button className="auth-submit" type="submit" disabled={status === 'saving'}><Save size={16} />{status === 'saving' ? 'Saving...' : status === 'saved' ? 'Saved' : 'Save profile'}</button>
          {status && status !== 'saving' && status !== 'saved' && <p className="profile-error">{status}</p>}
        </form>
      </div>
    </main>
  );
};

export default ProfileScreen;
