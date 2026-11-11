import React from 'react';
import { Routes, Route } from 'react-router-dom';
import './App.css';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import LoginScreen from './screens/LoginScreen';
import SignupScreen from './screens/SignupScreen';
import ResetPasword from './screens/ResetPasword';
import NewPasword from './screens/NewPasword';
import DashboardScreen from './screens/DashboardScreen';
import ServiceDetailScreen from './screens/ServiceDetailScreen';
import VerifyEmailScreen from './screens/VerifyEmailScreen';
import VulnerabilitiesScreen from './screens/VulnerabilitiesScreen';
import PhishingDetectorScreen from './screens/PhishingDetectorScreen';
import SecurityAuditsScreen from './screens/SecurityAuditsScreen';
import ClientAuditScreen from './screens/ClientAuditScreen';
import FileScannerScreen from './screens/FileScannerScreen';
import PasswordSecurityScreen from './screens/PasswordSecurityScreen';
import WebsiteSecurityScreen from './screens/WebsiteSecurityScreen';
import SimulationLabPage from './screens/SimulationLabPage';
import LandingPage from './screens/LandingPage';
import ProfileScreen from './screens/ProfileScreen';
import NotificationsScreen from './screens/NotificationsScreen';
import AIRakshakScreen from './screens/AIRakshakScreen';

function App() {
  return (
    <AuthProvider>
        <div className="App">
          <Routes>
            {/* Root Route (Redirects to /dashboard during bypass mode) */}
          <Route
            path="/"
            element={<LandingPage />}
          />
          <Route path="/login" element={<LoginScreen />} />
          <Route path="/signup" element={<SignupScreen />} />
          <Route path="/reset" element={<ResetPasword />} />
          <Route path="/newpassword/:token" element={<NewPasword />} />
          <Route path="/verify-email" element={<VerifyEmailScreen />} />
          <Route path="/profile" element={<ProtectedRoute><ProfileScreen /></ProtectedRoute>} />
          <Route path="/notifications" element={<ProtectedRoute><NotificationsScreen /></ProtectedRoute>} />
          <Route path="/ai-rakshak" element={<ProtectedRoute><AIRakshakScreen /></ProtectedRoute>} />

          {/* OWASP Protected Routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <DashboardScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/service/:id"
            element={
              <ProtectedRoute>
                <ServiceDetailScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/vulnerabilities"
            element={
              <ProtectedRoute>
                <VulnerabilitiesScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/phishing-detector"
            element={
              <ProtectedRoute>
                <PhishingDetectorScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/security-audits"
            element={
              <ProtectedRoute>
                <SecurityAuditsScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/file-scanner"
            element={
              <ProtectedRoute>
                <FileScannerScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/password-security"
            element={
              <ProtectedRoute>
                <PasswordSecurityScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/password-lab"
            element={
              <ProtectedRoute>
                <PasswordSecurityScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/website-security"
            element={
              <ProtectedRoute>
                <WebsiteSecurityScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/website-scanner"
            element={
              <ProtectedRoute>
                <WebsiteSecurityScreen />
              </ProtectedRoute>
            }
          />
          <Route
            path="/simulation-lab"
            element={
              <ProtectedRoute>
                <SimulationLabPage />
              </ProtectedRoute>
            }
          />
        </Routes>
      </div>
    </AuthProvider>
  );
}

export default App;
