/**
 * Registration component with Ed25519 key generation
 */

import { useCallback, useMemo } from 'react';
import { generateKeyPair, generateMasterKey, hashPassword, encryptPrivateKey } from '../utils/crypto';
import { register } from '../utils/api';
import { useForm } from '../hooks/useForm';
import { useAsync } from '../hooks/useAsync';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Alert } from './ui/Alert';

// Validation utility functions
const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_.-]+$/;
  if (!username || username.length < 3 || username.length > 24) {
    return 'Username must be between 3 and 24 characters';
  }
  if (!usernameRegex.test(username)) {
    return 'Username can only contain letters, numbers, underscores, hyphens, and periods';
  }
  return null;
};

const validateEmail = (email) => {
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  if (!email || !emailRegex.test(email)) {
    return 'Please enter a valid email address';
  }
  return null;
};

const validatePassword = (password) => {
  if (!password || password.length < 8) {
    return 'Password must be at least 8 characters';
  }
  if (password.length > 128) {
    return 'Password must be less than 128 characters';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password must contain at least one number';
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return 'Password must contain at least one special character';
  }
  return null;
};

export default function Register({ onSuccess, onSwitchToLogin }) {
  const { values, errors, handleChange, setFieldError, resetForm } = useForm({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const { loading, error, execute, clearError } = useAsync();

  const handleInputChange = useCallback((e) => {
    handleChange(e);
    clearError();
  }, [handleChange, clearError]);

  const validateForm = useCallback(() => {
    // Username validation
    const usernameError = validateUsername(values.username);
    if (usernameError) {
      setFieldError('username', usernameError);
      return false;
    }

    // Email validation
    const emailError = validateEmail(values.email);
    if (emailError) {
      setFieldError('email', emailError);
      return false;
    }

    // Password validation
    const passwordError = validatePassword(values.password);
    if (passwordError) {
      setFieldError('password', passwordError);
      return false;
    }

    // Confirm password validation
    if (values.password !== values.confirmPassword) {
      setFieldError('confirmPassword', 'Passwords do not match');
      return false;
    }

    return true;
  }, [values, setFieldError]);

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    await execute(async () => {
      // 1. Generate Ed25519 key pair
      const { privateKey, publicKeyPEM } = await generateKeyPair();

      // 2. Generate Master Key: PBKDF2(password, email)
      const masterKey = await generateMasterKey(values.password, values.email);

      // 3. Hash password with Argon2id: Argon2ID(masterKey, password)
      const passwordHash = await hashPassword(masterKey, values.password);

      // 4. Encrypt private key with Master Key and time-based IV
      const { encrypted, iv } = await encryptPrivateKey(privateKey, masterKey);

      // 5. Prepare registration data
      const registrationData = {
        username: values.username,
        email: values.email,
        password_hash: passwordHash,
        encrypted_private_key: encrypted,
        public_key: publicKeyPEM,
        encryption_iv: iv
      };

      // 6. Register with backend (signed request)
      const response = await register(registrationData, privateKey);

      // 7. Pass data to 2FA verification step (keys stored in memory only)
      onSuccess({
        ...response,
        privateKey: privateKey,
        masterKey: masterKey,
        username: values.username,
        email: values.email,
        password: values.password
      });
    });
  }, [values, validateForm, execute, onSuccess]);

  return (
    <div className="w-full max-w-md">
      <div className="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Create Account</h2>
          <p className="mt-2 text-gray-600 dark:text-gray-400">Join our secure chat platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <Input
            type="text"
            id="username"
            name="username"
            label="Username"
            value={values.username}
            onChange={handleInputChange}
            error={errors.username}
            minLength={3}
            maxLength={24}
            placeholder="Choose a username"
            disabled={loading}
            required
          />

          <Input
            type="email"
            id="email"
            name="email"
            label="Email Address"
            value={values.email}
            onChange={handleInputChange}
            error={errors.email}
            placeholder="your@email.com"
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
            minLength={8}
            placeholder="At least 8 characters"
            helpText="Must contain: uppercase, lowercase, number, and special character"
            disabled={loading}
            required
          />

          <Input
            type="password"
            id="confirmPassword"
            name="confirmPassword"
            label="Confirm Password"
            value={values.confirmPassword}
            onChange={handleInputChange}
            error={errors.confirmPassword}
            placeholder="Confirm your password"
            disabled={loading}
            required
          />

          {error && (
            <Alert type="error" message={error} onClose={clearError} />
          )}

          <Button
            type="submit"
            variant="primary"
            disabled={loading}
            loading={loading}
            fullWidth
          >
            Create Account
          </Button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Already have an account?{' '}
            <button
              onClick={onSwitchToLogin}
              className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-semibold transition-colors"
              disabled={loading}
            >
              Sign in
            </button>
          </p>
        </div>

        <div className="mt-8 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
          <p className="text-xs text-blue-800 dark:text-blue-300">
            <strong>🔒 Zero-Knowledge Security:</strong> Your private key is encrypted with your Master Key and stored encrypted on the server. Only you can decrypt it with your password.
          </p>
        </div>
      </div>
    </div>
  );
}
