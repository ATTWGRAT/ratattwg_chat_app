/**
 * Login component with signature verification
 */

import { useState } from 'react';
import { generateMasterKey, hashPassword, decryptPrivateKey } from '../utils/crypto';
import { login as apiLogin } from '../utils/api';
import { useAuth } from '../context/AuthContext';

export default function Login({ onSwitchToRegister }) {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    totpCode: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleChange = (e) => {
    const value = e.target.name === 'totpCode' 
      ? e.target.value.replace(/\D/g, '').slice(0, 6)
      : e.target.value;
    
    setFormData({
      ...formData,
      [e.target.name]: value
    });
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.email || !formData.password || formData.totpCode.length !== 6) {
      setError('Please fill in all fields with valid values');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // 1. Generate Master Key: PBKDF2(password, email)
      const masterKey = await generateMasterKey(formData.password, formData.email);

      // 2. Hash password: Argon2ID(masterKey, password)
      const passwordHash = await hashPassword(masterKey, formData.password);
      
      // 3. Send login request
      const response = await apiLogin(
        formData.email,
        passwordHash,
        formData.totpCode
      );

      // 4. Decrypt private key with Master Key
      const privateKey = await decryptPrivateKey(
        response.user.encrypted_private_key,
        response.user.encryption_iv,
        masterKey
      );

      // 5. Store session in auth context (with Master Key and private key in memory)
      await login(response.user, formData.password, masterKey, privateKey);

    } catch (error) {
      console.error('Login error:', error);
      if (error.message.includes('User not found')) {
        setError('No account found with this email. Please register first.');
      } else if (error.message.includes('Malformed')) {
        setError('Invalid password or corrupted key data');
      } else {
        setError(error.message || 'Login failed. Please check your credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md">
      <div className="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Welcome Back</h2>
          <p className="mt-2 text-gray-600 dark:text-gray-400">Sign in to your secure account</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Email
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
              className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 transition-all"
              placeholder="Enter your email"
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 transition-all"
              placeholder="Enter your password"
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="totpCode" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              2FA Code
            </label>
            <input
              type="text"
              id="totpCode"
              name="totpCode"
              value={formData.totpCode}
              onChange={handleChange}
              required
              maxLength={6}
              pattern="\d{6}"
              className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 text-center text-xl font-mono tracking-widest transition-all"
              placeholder="000000"
              disabled={loading}
              autoComplete="off"
            />
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400 text-center">
              Enter the code from your authenticator app
            </p>
          </div>

          {error && (
            <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || formData.totpCode.length !== 6}
            className="w-full py-3 px-4 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Signing In...
              </span>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Don't have an account?{' '}
            <button
              onClick={onSwitchToRegister}
              className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-semibold transition-colors"
              disabled={loading}
            >
              Create one
            </button>
          </p>
        </div>

        <div className="mt-8 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <p className="text-xs text-blue-800 dark:text-blue-300">
            <strong>🔒 Zero-Knowledge Security:</strong> Your private key is retrieved encrypted from the server and decrypted in memory only. Keys never leave your device unencrypted.
          </p>
        </div>
      </div>
    </div>
  );
}
