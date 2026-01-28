/**
 * Recovery Login component for users who lost access to authenticator app
 */

import { useState } from 'react';
import { generateMasterKey, hashPassword, decryptPrivateKey } from '../utils/crypto';
import { loginWithRecovery } from '../utils/api';
import { useAuth } from '../context/AuthContext';

export default function RecoveryLogin({ onBackToLogin }) {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    recoveryCode: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [warning, setWarning] = useState('');
  const { login } = useAuth();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.email || !formData.password || !formData.recoveryCode) {
      setError('Please fill in all fields');
      return;
    }

    setLoading(true);
    setError('');
    setWarning('');

    try {
      // 1. Generate Master Key: PBKDF2(password, email)
      const masterKey = await generateMasterKey(formData.password, formData.email);

      // 2. Hash password: Argon2ID(masterKey, password)
      const passwordHash = await hashPassword(masterKey, formData.password);
      
      // 3. Send recovery login request
      const response = await loginWithRecovery(
        formData.email,
        passwordHash,
        formData.recoveryCode
      );

      // Show warning if present
      if (response.warning) {
        setWarning(response.warning);
      }

      // 4. Decrypt private key with Master Key
      const privateKey = await decryptPrivateKey(
        response.user.encrypted_private_key,
        response.user.encryption_iv,
        masterKey
      );

      // 5. Store session in auth context (with Master Key and private key in memory)
      await login(response.user, formData.password, masterKey, privateKey);

    } catch (error) {
      console.error('Recovery login error:', error);
      if (error.message.includes('User not found')) {
        setError('No account found with this email. Please register first.');
      } else if (error.message.includes('Malformed')) {
        setError('Invalid password or corrupted key data');
      } else {
        setError(error.message || 'Login failed. Please check your credentials and recovery code.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md">
      <div className="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-orange-500 to-red-600 rounded-full mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Account Recovery</h2>
          <p className="mt-2 text-gray-600 dark:text-gray-400">Use a recovery code to regain access</p>
        </div>

        <div className="mb-6 p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg">
          <p className="text-sm text-orange-800 dark:text-orange-300">
            <strong>⚠️ Important:</strong> Recovery codes can only be used once. After login, you'll be required to set up 2FA again immediately.
          </p>
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
              className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 transition-all"
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
              className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 transition-all"
              placeholder="Enter your password"
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="recoveryCode" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Recovery Code
            </label>
            <input
              type="text"
              id="recoveryCode"
              name="recoveryCode"
              value={formData.recoveryCode}
              onChange={handleChange}
              required
              className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 font-mono transition-all"
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
              disabled={loading}
              autoComplete="off"
            />
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
              Enter one of your backup recovery codes
            </p>
          </div>

          {warning && (
            <div className="p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg">
              <p className="text-sm text-orange-800 dark:text-orange-300">{warning}</p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 px-4 bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Recovering Access...
              </span>
            ) : (
              'Recover Account'
            )}
          </button>
        </form>

        <div className="mt-6 text-center">
          <button
            onClick={onBackToLogin}
            className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
            disabled={loading}
          >
            ← Back to normal login
          </button>
        </div>

        <div className="mt-8 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <p className="text-xs text-blue-800 dark:text-blue-300">
            <strong>🔒 Security Note:</strong> After using a recovery code, you must immediately set up 2FA again. The used code will be permanently deleted.
          </p>
        </div>
      </div>
    </div>
  );
}
