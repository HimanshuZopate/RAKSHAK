import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';
import { Icon } from '@iconify/react';
import { IC } from '../utils/icons';

// Legacy lucide fallback for the service card rendering (iconKey from DB)
const iconMap = {
  ShieldAlert:  IC.shieldAlert,
  Users:        IC.users,
  FileText:     IC.fileScanner,
  Activity:     IC.activity,
  Server:       IC.server,
  Lock:         IC.lock,
  ShieldCheck:  IC.shield,
  KeyRound:     IC.password,
  Globe:        IC.website,
  GraduationCap: IC.simLab,
};

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { y: 20, opacity: 0 },
  visible: {
    y: 0,
    opacity: 1,
    transition: {
      type: 'spring',
      stiffness: 100,
      damping: 15,
    },
  },
};

/**
 * Format timestamp into readable relative time (e.g., '12m ago', '3h ago')
 */
const formatLastRun = (dateStr) => {
  if (!dateStr) return 'Never executed';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return 'Recently';

  const diffMs = Date.now() - d.getTime();
  const diffMins = Math.floor(diffMs / (1000 * 60));
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
};

const DashboardScreen = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [services, setServices] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  const navigate = useNavigate();
  const { user, logout } = useAuth();

  // Fetch live security services from backend REST endpoint
  const fetchServices = async () => {
    try {
      setIsLoading(true);
      setFetchError(null);
      const res = await api.get('/services');
      if (res.data?.services) {
        let hasService7 = false;
        let hasService8 = false;

        // Permanently filter out retired services (Intrusion Detection, API Monitoring, Data Encryption)
        const activeServices = res.data.services.filter((s) => {
          if ([4, 5, 6].includes(s.serviceId)) return false;
          const nameLower = (s.name || '').toLowerCase();
          if (
            nameLower.includes('intrusion') ||
            nameLower.includes('api monitoring') ||
            nameLower.includes('encryption')
          ) {
            return false;
          }
          return true;
        });

        // Guarantee service 2 renders as Phishing & Scam Detector regardless of legacy database state
        const sanitized = activeServices.map((s) => {
          if (s.serviceId === 7 || (s.name && s.name.toLowerCase().includes('password'))) {
            hasService7 = true;
          }
          if (s.serviceId === 8 || (s.name && s.name.toLowerCase().includes('website'))) {
            hasService8 = true;
          }
          if (s.serviceId === 2 || (s.name && s.name.toLowerCase().includes('access'))) {
            return {
              ...s,
              serviceId: 2,
              name: 'Phishing & Scam Detector',
              description:
                'Analyze suspicious URLs, emails, SMS messages, and online messages to identify phishing indicators, potential scams, and recommended safety actions.',
              iconKey: 'ShieldAlert',
              color: 'from-orange-500 to-red-600',
              shadow: 'shadow-orange-500/30',
              metrics: s.metrics && !s.metrics.toLowerCase().includes('user') ? s.metrics : 'Threat Analysis Ready',
            };
          }
          return s;
        });

        // Ensure Password Security Lab (Service #7) is included on the main dashboard
        if (!hasService7) {
          sanitized.push({
            serviceId: 7,
            name: 'Password Security Lab',
            description:
              'Evaluate password strength, identify predictable patterns, and generate secure passwords privately in your browser.',
            status: 'Active',
            iconKey: 'KeyRound',
            color: 'from-cyan-500 to-blue-600',
            shadow: 'shadow-cyan-500/30',
            metrics: 'Client-Side Analysis',
            severity: 'Low',
            lastRun: new Date(),
          });
        }

        // Ensure Website Security Scanner (Service #8) is included on the main dashboard
        if (!hasService8) {
          sanitized.push({
            serviceId: 8,
            name: 'Website Security Scanner',
            description:
              'Check HTTPS availability, inspect TLS certificate information, review HTTP security headers, and identify basic website configuration concerns.',
            status: 'Active',
            iconKey: 'Globe',
            color: 'from-blue-600 to-cyan-500',
            shadow: 'shadow-blue-500/30',
            metrics: 'Remote Configuration Scan',
            severity: 'Low',
            lastRun: new Date(),
          });
        }

        setServices(sanitized);
      }
    } catch (err) {
      console.error('Error loading services:', err);
      setFetchError('Failed to synchronize with security service engine.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, []);

  const filteredServices = services
    .filter((s) => ![4, 5, 6].includes(s.serviceId))
    .filter((s) => {
      const name = (s.name || s.title || '').toLowerCase();
      if (
        name.includes('intrusion') ||
        name.includes('api monitoring') ||
        name.includes('encryption')
      ) {
        return false;
      }
      return (
        name.includes(searchTerm.toLowerCase()) ||
        (s.description || '').toLowerCase().includes(searchTerm.toLowerCase())
      );
    });

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex overflow-hidden">
      {/* Sidebar */}
      <motion.div
        initial={{ width: 280 }}
        animate={{ width: sidebarOpen ? 280 : 80 }}
        transition={{ duration: 0.25, ease: 'easeInOut' }}
        className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl border-r border-slate-200 dark:border-slate-800 flex-shrink-0 z-20 hidden md:flex flex-col shadow-2xl transition-all"
      >
        <div className="h-20 flex items-center justify-between px-6 border-b border-slate-200 dark:border-slate-800">
          {sidebarOpen ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.15, delay: 0.25 }}
              className="font-black text-2xl bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600"
            >
              Rakshak
            </motion.div>
          ) : (
            <Icon icon={IC.shieldAlert} width={32} height={32} className="text-blue-600 mx-auto" />
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
          >
            <Icon icon={IC.menu} width={24} height={24} />
          </button>
        </div>

        <div className="flex-1 py-8 px-4 flex flex-col gap-2">
          {[
            { icon: IC.dashboard,   label: 'Dashboard',     active: true,  path: '/dashboard' },
            { icon: IC.vulns,       label: 'Vulnerabilities', active: false, path: '/vulnerabilities' },
            { icon: IC.simLab,      label: 'Simulation Lab', active: false, path: '/simulation-lab' },
            { icon: IC.shield,      label: 'AI RAKSHAK',      active: false, path: '/ai-rakshak' },
          ].map((item, index) => (
            <div
              key={index}
              onClick={() => item.path !== '#' && navigate(item.path)}
              className={`flex items-center justify-between px-4 py-3 rounded-xl cursor-pointer transition-all ${
                item.active
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <div className="flex items-center gap-4">
                <Icon icon={item.icon} width={22} height={22} className="flex-shrink-0" />
                {sidebarOpen && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.15, delay: 0.25 }}
                    className="font-semibold"
                  >
                    {item.label}
                  </motion.span>
                )}
              </div>
              {sidebarOpen && item.badge && (
                <span className="badge badge-error badge-sm text-white font-bold">{item.badge}</span>
              )}
            </div>
          ))}
        </div>

        {/* Logout Button */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800">
          <div
            onClick={logout}
            className="flex items-center gap-4 px-4 py-3 text-slate-600 dark:text-slate-400 hover:text-red-500 cursor-pointer rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
          >
            <Icon icon={IC.logout} width={22} height={22} className="flex-shrink-0" />
            {sidebarOpen && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.15, delay: 0.25 }}
                className="font-semibold"
              >
                Logout
              </motion.span>
            )}
          </div>
        </div>
      </motion.div>

      {/* Mobile Drawer Navigation */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <div className="fixed inset-0 z-50 md:hidden flex">
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMobileMenuOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm"
            />
            {/* Drawer */}
            <motion.div
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="relative w-72 bg-white dark:bg-slate-900 h-full p-6 flex flex-col justify-between shadow-2xl z-10"
            >
              <div>
                <div className="flex items-center justify-between pb-6 border-b border-slate-200 dark:border-slate-800">
                  <div className="font-black text-2xl bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600">
                    Rakshak
                  </div>
                  <button
                    onClick={() => setMobileMenuOpen(false)}
                    className="p-2 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                  >
                  <Icon icon={IC.close} width={20} height={20} />
                  </button>
                </div>

                <div className="py-6 flex flex-col gap-2">
                  {[
                    { icon: IC.dashboard,   label: 'Dashboard',      active: true,  path: '/dashboard' },
                    { icon: IC.vulns,    label: 'Vulnerabilities', active: false, path: '/vulnerabilities' },
                    { icon: IC.simLab,   label: 'Simulation Lab',  active: false, path: '/simulation-lab' },
                    { icon: IC.shield,   label: 'AI RAKSHAK',       active: false, path: '/ai-rakshak' },
                  ].map((item, index) => (
                    <div
                      key={index}
                      onClick={() => {
                        setMobileMenuOpen(false);
                        if (item.path !== '#') navigate(item.path);
                      }}
                      className={`flex items-center justify-between px-4 py-3 rounded-xl cursor-pointer transition-all ${
                        item.active
                          ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30'
                          : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-4">
                        <Icon icon={item.icon} width={22} height={22} className="flex-shrink-0" />
                        <span className="font-semibold">{item.label}</span>
                      </div>
                      {item.badge && (
                        <span className="badge badge-error badge-sm text-white font-bold">{item.badge}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
                <div
                  onClick={() => {
                    setMobileMenuOpen(false);
                    logout();
                  }}
                  className="flex items-center gap-4 px-4 py-3 text-slate-600 dark:text-slate-400 hover:text-red-500 cursor-pointer rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                >
                  <Icon icon={IC.logout} width={22} height={22} className="flex-shrink-0" />
                  <span className="font-semibold">Logout</span>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Top Header */}
        <header className="h-20 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl border-b border-slate-200 dark:border-slate-800 px-8 flex items-center justify-between z-10">
          <div className="flex items-center gap-4 flex-1">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="md:hidden text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
            >
              <Icon icon={IC.menu} width={24} height={24} />
            </button>
            <div className="relative w-full max-w-md hidden sm:block">
              <Icon icon={IC.search} width={20} height={20} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search security tools, CVEs, or status..."
                className="w-full bg-slate-100 dark:bg-slate-800 border-none rounded-full py-2.5 pl-10 pr-4 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white"
              />
            </div>
          </div>

          <div className="flex items-center gap-6">
            <button
              onClick={fetchServices}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-colors"
              title="Refresh services from server"
            >
              <Icon icon={IC.refresh} width={20} height={20} className={`${isLoading ? 'animate-spin text-blue-500' : ''}`} />
            </button>

            <button             onClick={() => navigate('/notifications')}
            className="relative p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-colors"
            title="View notifications and activity">
              <Icon icon={IC.bell} width={20} height={20} />
              <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-white dark:border-slate-900"></span>
            </button>

            {/* Authenticated User Badge */}
            <button onClick={() => navigate('/profile')} className="flex items-center gap-3 text-left" title="Open profile">
              <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-600 p-0.5 shadow-md">
                <div className="w-full h-full rounded-full border-2 border-white dark:border-slate-900 overflow-hidden bg-white">
                  <img
                    src={user?.avatarUrl || `https://api.dicebear.com/7.x/avataaars/svg?seed=${user?.email || 'SecOps'}&backgroundColor=b6e3f4`}
                    alt="User Avatar"
                  />
                </div>
              </div>
              <div className="hidden lg:block text-sm">
                <p className="font-bold text-slate-900 dark:text-white truncate max-w-[180px]">
                  {user?.email || 'Security Officer'}
                </p>
                <p className="text-slate-500 dark:text-slate-400 text-xs flex items-center gap-1">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                  Role: {user?.role || 'authorized'}
                </p>
              </div>
              </button>
            </div>
        </header>

        {/* Dashboard Content */}
        <main className="flex-1 overflow-y-auto p-6 sm:p-8">
          <div className="max-w-7xl mx-auto space-y-8">
            {/* Page Header */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
              <div>
                <motion.h1
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="text-3xl sm:text-4xl font-black text-slate-900 dark:text-white tracking-tight"
                >
                  Security Operations Center
                </motion.h1>
                <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm sm:text-base">
                  Real-time telemetry, automated scans, and identity defense monitoring.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-xs font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                  Database Synced ({services.length} Tools)
                </span>
              </div>
            </div>

            {/* Error Banner */}
            {fetchError && (
              <div className="p-4 rounded-2xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-300 text-sm flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Icon icon={IC.warning} width={20} height={20} className="w-5 h-5 flex-shrink-0 text-amber-500" />
                  <span>{fetchError}</span>
                </div>
                <button
                  onClick={fetchServices}
                  className="btn btn-xs btn-outline border-amber-500 text-amber-700 dark:text-amber-300 normal-case"
                >
                  Retry Connection
                </button>
              </div>
            )}

            {/* Loading Skeleton */}
            {isLoading && services.length === 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {[1, 2, 3, 4, 5, 6].map((i) => (
                  <div
                    key={i}
                    className="h-64 rounded-3xl bg-slate-200/60 dark:bg-slate-900/60 animate-pulse p-6 border border-slate-200 dark:border-slate-800"
                  ></div>
                ))}
              </div>
            ) : (
              /* Dynamic Services Grid mapped over MongoDB collection */
              <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6"
              >
                {filteredServices.map((service) => {
                  const iconStr = iconMap[service.iconKey] || IC.shieldAlert;
                  const serviceTargetId = service.serviceId || service._id;
                  const isAuditCard = service.serviceId === 3 || (service.name && service.name.toLowerCase().includes('security audit'));
                  const isPhishingCard = service.serviceId === 2 || (service.name && service.name.toLowerCase().includes('phishing'));
                  const isPasswordCard = service.serviceId === 7 || (service.name && service.name.toLowerCase().includes('password'));
                  const isWebsiteCard = service.serviceId === 8 || (service.name && service.name.toLowerCase().includes('website'));

                  return (
                    <motion.div
                      key={service._id || service.serviceId}
                      variants={itemVariants}
                      whileHover={{ y: -5, scale: 1.01 }}
                      onClick={() => navigate('/service/' + serviceTargetId)}
                      className={`bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl rounded-3xl p-6 shadow-xl border relative group overflow-hidden cursor-pointer transition-all ${
                        isAuditCard
                          ? 'border-cyan-500/30 dark:border-cyan-500/30 hover:border-cyan-500 dark:hover:border-cyan-400 hover:shadow-cyan-500/10'
                          : isPhishingCard
                          ? 'border-orange-500/30 dark:border-orange-500/30 hover:border-orange-500 dark:hover:border-orange-400 hover:shadow-orange-500/10'
                          : isPasswordCard
                          ? 'border-cyan-400/30 dark:border-cyan-400/30 hover:border-cyan-400 dark:hover:border-cyan-300 hover:shadow-cyan-500/20'
                          : isWebsiteCard
                          ? 'border-blue-500/30 dark:border-blue-500/30 hover:border-cyan-400 dark:hover:border-cyan-400 hover:shadow-cyan-500/20'
                          : 'border-slate-100 dark:border-slate-800/80 hover:border-slate-300 dark:hover:border-slate-700'
                      }`}
                    >
                      {/* Gradient ambient glow */}
                      <div
                        className={`absolute top-0 right-0 w-36 h-36 bg-gradient-to-br ${
                          service.color || 'from-blue-500 to-indigo-600'
                        } opacity-10 rounded-bl-full -mr-8 -mt-8 transition-transform group-hover:scale-125 duration-500`}
                      ></div>

                      {/* Header Row */}
                      <div className="flex justify-between items-start mb-5">
                        <div
                          className={`w-14 h-14 rounded-2xl bg-gradient-to-br ${
                            service.color || 'from-blue-500 to-indigo-600'
                          } shadow-lg ${service.shadow || 'shadow-blue-500/20'} flex items-center justify-center text-white`}
                        >
                        <Icon icon={iconStr} width={28} height={28} className="text-white" />
                        </div>

                        {/* Status Badge & Specialty Pills */}
                        <div className="flex items-center gap-2">
                          {isAuditCard && (
                            <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30">
                              Client Audit
                            </span>
                          )}
                          {isPhishingCard && (
                            <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/30">
                              Threat Detector
                            </span>
                          )}
                          {isPasswordCard && (
                            <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                              Password Lab
                            </span>
                          )}
                          {isWebsiteCard && (
                            <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
                              Website Scanner
                            </span>
                          )}
                          <div
                            className={`px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1.5 ${
                              service.status === 'Active'
                                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-500/20'
                                : service.status === 'Pending'
                                ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-950/40 dark:text-yellow-400 border border-yellow-500/20'
                                : 'bg-orange-100 text-orange-700 dark:bg-orange-950/40 dark:text-orange-400 border border-orange-500/20'
                            }`}
                          >
                            <span
                              className={`w-2 h-2 rounded-full ${
                                service.status === 'Active'
                                  ? 'bg-emerald-500'
                                  : service.status === 'Pending'
                                  ? 'bg-yellow-500'
                                  : 'bg-orange-500'
                              }`}
                            ></span>
                            {service.status}
                          </div>
                        </div>
                      </div>

                      {/* Service Title & Description */}
                      <h3 className={`text-xl font-bold text-slate-900 dark:text-white mb-2 transition-colors ${
                        isAuditCard
                          ? 'group-hover:text-cyan-600 dark:group-hover:text-cyan-400'
                          : isPhishingCard
                          ? 'group-hover:text-orange-600 dark:group-hover:text-orange-400'
                          : isPasswordCard
                          ? 'group-hover:text-cyan-500 dark:group-hover:text-cyan-300'
                          : isWebsiteCard
                          ? 'group-hover:text-cyan-400 dark:group-hover:text-cyan-300'
                          : 'group-hover:text-blue-600 dark:group-hover:text-blue-400'
                      }`}>
                        {service.name || service.title}
                      </h3>
                      <p className="text-slate-500 dark:text-slate-400 text-sm leading-relaxed mb-6 h-12 overflow-hidden text-ellipsis line-clamp-2">
                        {service.description}
                      </p>

                      {/* Footer Row with live Last Run timestamp and metrics */}
                      <div className="flex items-center justify-between pt-4 border-t border-slate-100 dark:border-slate-800">
                        <div className="flex flex-col">
                          <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
                            {service.metrics}
                          </span>
                          <span className="text-[11px] text-slate-400 dark:text-slate-500 font-mono flex items-center gap-1 mt-0.5">
                            <Icon icon={IC.clock} width={12} height={12} />
                            Run: {formatLastRun(service.lastRun)}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          {isAuditCard && (
                            <span className="text-xs font-bold text-cyan-600 dark:text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                              Run Audit
                            </span>
                          )}
                          {isPhishingCard && (
                            <span className="text-xs font-bold text-orange-600 dark:text-orange-400 group-hover:translate-x-0.5 transition-transform">
                              Analyze Threat
                            </span>
                          )}
                          {isPasswordCard && (
                            <span className="text-xs font-bold text-cyan-600 dark:text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                              Open Lab
                            </span>
                          )}
                          {isWebsiteCard && (
                            <span className="text-xs font-bold text-cyan-400 group-hover:translate-x-0.5 transition-transform">
                              Scan Website
                            </span>
                          )}
                          <button
                            className={`w-9 h-9 rounded-full flex items-center justify-center bg-slate-100 dark:bg-slate-800 text-slate-500 group-hover:bg-gradient-to-r ${
                              service.color || 'from-blue-600 to-indigo-600'
                            } group-hover:text-white transition-all shadow-md group-hover:translate-x-1`}
                          >
                            <Icon icon={IC.chevRight} width={16} height={16} />
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </motion.div>
            )}
          </div>
        </main>
      </div>

      {/* Floating AI RAKSHAK Quick Launcher */}
      <motion.button
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        whileHover={{ scale: 1.05, y: -2 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => navigate('/ai-rakshak')}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2.5 px-4 py-3 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold text-sm shadow-xl shadow-blue-500/30 border border-blue-400/30 backdrop-blur-md cursor-pointer group"
        title="Open AI RAKSHAK Cyber Assistant"
        aria-label="Open AI RAKSHAK"
      >
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-300 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400" />
        </span>
        <Icon icon={IC.shield} width={18} height={18} />
        <span>Ask AI RAKSHAK</span>
      </motion.button>
    </div>
  );
};

export default DashboardScreen;
