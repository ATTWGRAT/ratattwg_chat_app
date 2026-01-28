/**
 * Login component with signature verification
 */

import { useCallback } from 'react';
import { generateMasterKey, hashPassword, decryptPrivateKey } from '../utils/crypto';
import { login as apiLogin } from '../utils/api';
import { useAuth } from '../context/AuthContext';
import { useForm } from '../hooks/useForm';
import { useAsync } from '../hooks/useAsync';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Alert } from './ui/Alert';

export default function Login({ onSwitchToRegister, onSwitchToRecovery }) {
  const { login } = useAuth();
  const { values, errors, handleChange, setFieldValue, setFieldError } = useForm({
    email: '',
    password: '',
    totpCode: ''
  });
  const { loading, error, execute, clearError } = useAsync();

  const handleTotpChange = useCallback((e) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
    setFieldValue('totpCode', value);
    clearError();
  }, [setFieldValue, clearError]);

  const handleInputChange = useCallback((e) => {
    handleChange(e);
    clearError();
  }, [handleChange, clearError]);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    
    // Validation
    if (!values.email || !values.password || values.totpCode.length !== 6) {
      setFieldError('totpCode', 'Please fill in all fields with valid values');
      return;
    }

    await execute(async () => {
      // 1. Generate Master Key: PBKDF2(password, email)
      const masterKey = await generateMasterKey(values.password, values.email);

      // 2. Hash password: Argon2ID(masterKey, password)
      const passwordHash = await hashPassword(masterKey, values.password);
      
      // 3. Send login request
      const response = await apiLogin(
        values.email,
        passwordHash,
        values.totpCode
      );

      // 4. Decrypt private key with Master Key
      const privateKey = await decryptPrivateKey(
        response.user.encrypted_private_key,
        response.user.encryption_iv,
        masterKey
      );

      // 5. Store session in auth context (with Master Key and private key in memory)
      await login(response.user, values.password, masterKey, privateKey);
    });
  }, [values, execute, login, setFieldError]);

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
          <Input
            type="email"
            id="email"
            name="email"
            label="Email"
            value={values.email}
            onChange={handleInputChange}
            error={errors.email}
            placeholder="Enter your email"
            disabled={loading}
            required
          />

          <Input
            type="password"
            id="password"
            name="password"
            label="Password"
            value={values.password}
            onChange={handleInputChange}
            error={errors.password}
            placeholder="Enter your password"
            disabled={loading}
            required
          />

          <div>
            <Input
              type="text"
              id="totpCode"
              name="totpCode"
              label="2FA Code"
              value={values.totpCode}
              onChange={handleTotpChange}
              error={errors.totpCode}
              maxLength={6}
              pattern="\d{6}"
              className="text-center text-xl font-mono tracking-widest"
              placeholder="000000"
              disabled={loading}
              autoComplete="off"
              required
            />
            <p className="mt-2 text-xs text-gray-500 dark:text-gray-400 text-center">
              Enter the code from your authenticator app
            </p>
            <div className="mt-2 text-center">
              <button
                type="button"
                onClick={onSwitchToRecovery}
                className="text-xs text-orange-600 dark:text-orange-400 hover:text-orange-700 dark:hover:text-orange-300 font-medium transition-colors"
                disabled={loading}
              >
                Can't access your authenticator? Use a recovery code →
              </button>
            </div>
          </div>

          {error && (
            <Alert type="error" message={error} onClose={clearError} />
          )}

          <Button
            type="submit"
            variant="primary"
            disabled={loading || values.totpCode.length !== 6}
            loading={loading}
            fullWidth
          >
            Sign In
          </Button>
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
