/**
 * Authentication context for managing user state and private keys
 * All sensitive data is stored in memory only (zero-knowledge architecture)
 */

import { createContext, useContext, useState, useEffect } from 'react';
import { getCurrentUser, logout as apiLogout } from '../utils/api';

console.log('AuthContext loaded');

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  console.log('AuthProvider rendering');
  const [user, setUser] = useState(null);
  const [privateKey, setPrivateKey] = useState(null); // Stored in memory only
  const [masterKey, setMasterKey] = useState(null); // Stored in memory only
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Check if user is already logged in (on mount)
  useEffect(() => {
    const checkAuth = async () => {
      try {
        // If we have a private key in memory, verify the session
        if (privateKey) {
          const userData = await getCurrentUser(privateKey);
          setUser(userData);
        }
      } catch (error) {
        // Session expired or invalid
        console.error('Auth check failed:', error);
        setUser(null);
        setPrivateKey(null);
        setMasterKey(null);
      } finally {
        setLoading(false);
      }
    };
    
    checkAuth();
  }, []);

  /**
   * Login user - store Master Key and private key in memory
   * @param {Object} userData - User data from login response
   * @param {string} password - Plain text password (for reference, not stored)
   * @param {Uint8Array} userMasterKey - Master Key
   * @param {Uint8Array} userPrivateKey - Decrypted private key
   */
  const login = async (userData, password, userMasterKey, userPrivateKey) => {
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
  };

  /**
   * Logout user - clear all sensitive data from memory
   */
  const logout = async () => {
    try {
      if (privateKey) {
        await apiLogout(privateKey);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Always clear local state
      setUser(null);
      setPrivateKey(null);
      setMasterKey(null);
      setError(null);
    }
  };

  /**
   * Complete registration - store private key and Master Key after 2FA verification
   * @param {Object} userData - User data from registration
   * @param {Uint8Array} newPrivateKey - Generated private key
   * @param {Uint8Array} newMasterKey - Generated Master Key
   */
  const completeRegistration = (userData, newPrivateKey, newMasterKey) => {
    setPrivateKey(newPrivateKey);
    setMasterKey(newMasterKey);
    setUser(userData);
    setError(null);
  };

  const value = {
    user,
    privateKey,
    masterKey,
    loading,
    error,
    login,
    logout,
    completeRegistration,
    isAuthenticated: !!user && !!privateKey && !!masterKey
  };

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
