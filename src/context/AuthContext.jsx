import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api from '../utils/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  /**
   * Verify session by fetching user info from backend /api/auth/me
   * The browser automatically attaches HttpOnly accessToken or refreshToken cookies.
   */
  const checkAuth = useCallback(async () => {
    try {
      setIsLoading(true);
      const res = await api.get('/auth/me');
      if (res.data?.user) {
        setUser(res.data.user);
        setIsAuthenticated(true);
      } else {
        setUser(null);
        setIsAuthenticated(false);
      }
    } catch (err) {
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Listen for session expiration events from Axios interceptor
  useEffect(() => {
    checkAuth();

    const handleSessionExpired = () => {
      setUser(null);
      setIsAuthenticated(false);
    };

    window.addEventListener('auth:session_expired', handleSessionExpired);
    return () => {
      window.removeEventListener('auth:session_expired', handleSessionExpired);
    };
  }, [checkAuth]);

  /**
   * Authenticate with email & password
   */
  const login = async (email, password) => {
    setError(null);
    try {
      const res = await api.post('/auth/login', { email, password });
      if (res.data?.user) {
        setUser(res.data.user);
        setIsAuthenticated(true);
      }
      return { success: true, user: res.data.user };
    } catch (err) {
      const errorMsg =
        err.response?.data?.error || 'Login failed. Please check your credentials.';
      const errorCode = err.response?.data?.code;
      setError(errorMsg);
      return {
        success: false,
        error: errorMsg,
        code: errorCode,
        email: err.response?.data?.email,
      };
    }
  };

  /**
   * Register with email & password
   */
  const register = async (email, password) => {
    setError(null);
    try {
      const res = await api.post('/auth/register', { email, password });
      if (res.data?.user) {
        setUser(res.data.user);
        setIsAuthenticated(true);
      }
      return {
        success: true,
        message: res.data?.message || 'Registration successful!',
        email: res.data?.email || email,
      };
    } catch (err) {
      const errorMsg =
        err.response?.data?.error || 'Registration failed. Please try again.';
      setError(errorMsg);
      return { success: false, error: errorMsg };
    }
  };

  /**
   * Email verification handler
   */
  const verifyEmail = async (token) => {
    setError(null);
    try {
      const res = await api.get(`/auth/verify-email?token=${token}`);
      if (res.data?.user) {
        setUser(res.data.user);
        setIsAuthenticated(true);
      }
      return {
        success: true,
        message: res.data?.message || 'Email successfully verified!',
        user: res.data?.user,
      };
    } catch (err) {
      const errorMsg =
        err.response?.data?.error || 'Email verification failed or token has expired.';
      return { success: false, error: errorMsg };
    }
  };

  /**
   * Resend verification link
   */
  const resendVerification = async (email) => {
    try {
      const res = await api.post('/auth/resend-verification', { email });
      return {
        success: true,
        message: res.data?.message || 'Verification link sent!',
      };
    } catch (err) {
      return {
        success: false,
        error:
          err.response?.data?.error ||
          'Failed to resend verification email. Please try again later.',
      };
    }
  };

  /**
   * Invalidate session and clear cookies
   */
  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setUser(null);
      setIsAuthenticated(false);
      window.location.href = '/';
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        error,
        login,
        register,
        logout,
        checkAuth,
        verifyEmail,
        resendVerification,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
