import React, { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Bell, CheckCircle2, RefreshCw, ShieldAlert } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';

const NotificationsScreen = () => {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadNotifications = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [response, recommendationResponse] = await Promise.all([
        api.get('/audits?limit=50'),
        api.get('/ai/recommendations').catch(() => ({ data: { recommendations: [] } })),
      ]);
      setEvents(response.data?.events || []);
      setRecommendations(recommendationResponse.data?.recommendations || []);
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'Unable to load notifications.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadNotifications(); }, [loadNotifications]);

  return (
    <main className="notifications-page">
      <div className="notifications-panel">
        <div className="notifications-header"><button className="profile-back" onClick={() => navigate('/dashboard')}><ArrowLeft size={17} /> Dashboard</button><button className="notification-refresh" onClick={loadNotifications} disabled={loading}><RefreshCw size={17} className={loading ? 'spin' : ''} /> Refresh</button></div>
        <div className="notifications-title"><Bell size={25} /><div><p className="auth-kicker">ACTIVITY CENTER</p><h1>Notifications & activity</h1><p>Recent actions and security events recorded for your account.</p></div></div>
        {error && <div className="notification-error">{error}</div>}
        {!loading && !error && events.length === 0 && <div className="notification-empty"><ShieldAlert size={28} /><h2>No activity yet</h2><p>Your scans and security actions will appear here.</p></div>}
        <div className="notification-list">{events.map((event) => <article className="notification-item" key={event.id || event.eventId}><div className="notification-icon"><CheckCircle2 size={18} /></div><div><h2>{(event.action || 'Security activity').replaceAll('_', ' ')}</h2><p>{event.source || event.category || 'Rakshak'} · {event.status || 'recorded'}</p></div><time>{event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Recently'}</time></article>)}</div>
        {recommendations.length > 0 && <section className="recommendation-section"><h2>Recommended next steps</h2>{recommendations.map((item, index) => <article className="notification-item recommendation-item" key={`${item.title}-${index}`}><div className="notification-icon"><ShieldAlert size={18} /></div><div><h2>{item.title}</h2><p>{item.reason} {item.suggestedAction}</p></div><strong>{item.priority}</strong></article>)}</section>}
      </div>
    </main>
  );
};

export default NotificationsScreen;
