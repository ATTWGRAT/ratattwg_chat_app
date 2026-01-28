/**
 * Authentication context for managing user state and private keys
 * All sensitive data is stored in memory only (zero-knowledge architecture)
 */

import { createContext, useContext, useState, useEffect, useMemo, useCallback } from 'react';
import { getCurrentUser, logout as apiLogout } from '../utils/api';
import { disconnectSocket, initializeSocket, onForceLogout } from '../utils/socket';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [privateKey, setPrivateKey] = useState(null); // Stored in memory only
  const [masterKey, setMasterKey] = useState(null); // Stored in memory only
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Check if user is already logged in (on mount only)
  useEffect(() => {
    // No auth check needed on mount since keys are memory-only
    // Keys will be set during login/registration
    setLoading(false);
  }, []);

  /**
   * Login user - store Master Key and private key in memory
   * @param {Object} userData - User data from login response
   * @param {string} password - Plain text password (for reference, not stored)
   * @param {Uint8Array} userMasterKey - Master Key
   * @param {Uint8Array} userPrivateKey - Decrypted private key
   */
  const login = useCallback(async (userData, password, userMasterKey, userPrivateKey) => {
    try {
      // Store in memory
      setMasterKey(userMasterKey);
      setPrivateKey(userPrivateKey);
      setUser(userData);
      setError(null);
      return true;
    } catch (error) {
      console.error('Login error:', error);
      setError('Failed to store authentication data');
      return false;
    }
  }, []);

  /**
   * Listen for force logout from server (logged in from another location)
   */
  useEffect(() => {
    if (!user) return;

    // Initialize socket
    initializeSocket();
    
    // Set up force logout listener
    const handleForceLogout = (data) => {
      // Logout without calling API (session already invalidated)
      disconnectSocket();
      setUser(null);
      setPrivateKey(null);
      setMasterKey(null);
      localStorage.removeItem('user');
      // Show alert to user
      alert(data.message || 'You have been logged out because you logged in from another location.');
      // Redirect to login
      window.location.href = '/';
    };
    
    onForceLogout(handleForceLogout);
    
    // Cleanup on unmount or when user changes
    return () => {
      // Don't disconnect here as it might be used by other components
    };
  }, [user?.id]); // Only re-run if user ID changes (login/logout), not on user object updates

  /**
   * Logout user - clear all sensitive data from memory
   */
  const logout = useCallback(async () => {
    try {
      if (privateKey) {
        await apiLogout(privateKey);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Disconnect WebSocket before clearing state
      disconnectSocket();
      
      // Always clear local state
      setUser(null);
      setPrivateKey(null);
      setMasterKey(null);
      setError(null);
    }
  }, [privateKey]);

  /**
   * Complete registration - store private key and Master Key after 2FA verification
   * @param {Object} userData - User data from registration
   * @param {Uint8Array} newPrivateKey - Generated private key
   * @param {Uint8Array} newMasterKey - Generated Master Key
   */
  const completeRegistration = useCallback((userData, newPrivateKey, newMasterKey) => {
    setPrivateKey(newPrivateKey);
    setMasterKey(newMasterKey);
    setUser(userData);
    setError(null);
  }, []);

  const value = useMemo(() => ({
    user,
    privateKey,
    masterKey,
    loading,
    error,
    login,
    logout,
    completeRegistration,
    isAuthenticated: !!user && !!privateKey && !!masterKey
  }), [user, privateKey, masterKey, loading, error, login, logout, completeRegistration]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
