/**
 * 2FA Reset component for users who logged in with recovery code
 */

import { useState } from 'react';
import { reset2FA, verify2FAReset } from '../utils/api';

export default function TwoFAReset({ onResetComplete }) {
  const [step, setStep] = useState('init'); // 'init', 'verify'
  const [resetData, setResetData] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showRecoveryCodes, setShowRecoveryCodes] = useState(true);

  const handleInitiateReset = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await reset2FA();
      setResetData(response);
      setStep('verify');
    } catch (error) {
      console.error('2FA reset initiation error:', error);
      setError(error.message || 'Failed to initiate 2FA reset');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    
    if (totpCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setLoading(true);
    setError('');

    try {
      await verify2FAReset(totpCode);
      onResetComplete();
    } catch (error) {
      console.error('2FA verification error:', error);
      setError(error.message || 'Failed to verify 2FA code');
    } finally {
      setLoading(false);
    }
  };

  const copyRecoveryCodes = () => {
    const codesText = resetData.recovery_codes.join('\n');
    navigator.clipboard.writeText(codesText).then(() => {
      alert('Recovery codes copied to clipboard!');
    });
  };

  const downloadRecoveryCodes = () => {
    const codesText = resetData.recovery_codes.join('\n');
    const blob = new Blob([`Secure Chat App - Recovery Codes\nGenerated: ${new Date().toLocaleString()}\n\n${codesText}\n\nKeep these codes safe! Each code can only be used once.`], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recovery-codes-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  if (step === 'init') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-orange-50 via-red-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8">
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-orange-500 to-red-600 rounded-full mb-4">
                <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h2 className="text-3xl font-bold text-gray-900 dark:text-white">2FA Reset Required</h2>
              <p className="mt-2 text-gray-600 dark:text-gray-400">You used a recovery code to log in</p>
            </div>

            <div className="mb-6 p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg">
              <p className="text-sm text-orange-800 dark:text-orange-300 mb-2">
                <strong>⚠️ Security Alert:</strong>
              </p>
              <p className="text-sm text-orange-800 dark:text-orange-300">
                For your security, you must set up 2FA again after using a recovery code. This ensures your account remains protected.
              </p>
            </div>

            {error && (
              <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              </div>
            )}

            <button
              onClick={handleInitiateReset}
              disabled={loading}
              className="w-full py-3 px-4 bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Setting Up...
                </span>
              ) : (
                'Set Up New 2FA'
              )}
            </button>

            <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
              <p className="text-xs text-blue-800 dark:text-blue-300">
                <strong>📱 What you'll need:</strong> An authenticator app like Google Authenticator, Authy, or Microsoft Authenticator installed on your phone.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-orange-50 via-red-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-2xl">
        <div className="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-orange-500 to-red-600 rounded-full mb-4">
              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Set Up New 2FA</h2>
            <p className="mt-2 text-gray-600 dark:text-gray-400">Scan the QR code with your authenticator app</p>
          </div>

          {/* QR Code Section */}
          <div className="mb-8">
            <div className="bg-white p-6 rounded-xl border-4 border-orange-200 dark:border-orange-800 mx-auto w-fit">
              <img src={resetData.qr_code} alt="2FA QR Code" className="w-64 h-64" />
            </div>
            
            <div className="mt-4 text-center">
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Can't scan? Enter this code manually:</p>
              <div className="bg-gray-100 dark:bg-gray-700 px-4 py-2 rounded-lg inline-block">
                <code className="text-sm font-mono text-gray-900 dark:text-white">{resetData.secret}</code>
              </div>
            </div>
          </div>

          {/* Recovery Codes Section */}
          {showRecoveryCodes && (
            <div className="mb-8">
              <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-6">
                <div className="flex items-start mb-4">
                  <svg className="w-6 h-6 text-orange-600 dark:text-orange-400 mr-3 flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-orange-900 dark:text-orange-100 mb-2">New Recovery Codes</h3>
                    <p className="text-sm text-orange-800 dark:text-orange-300 mb-4">
                      Save these codes now! You'll need them if you lose access to your authenticator app. Each code can only be used once.
                    </p>
                    
                    <div className="grid grid-cols-2 gap-3 mb-4">
                      {resetData.recovery_codes.map((code, index) => (
                        <div key={index} className="bg-white dark:bg-gray-800 px-3 py-2 rounded border border-orange-200 dark:border-orange-700">
                          <span className="text-xs text-gray-500 dark:text-gray-400 mr-2">{index + 1}.</span>
                          <code className="text-sm font-mono text-gray-900 dark:text-white">{code}</code>
                        </div>
                      ))}
                    </div>
                    
                    <div className="flex gap-3">
                      <button
                        onClick={copyRecoveryCodes}
                        className="flex-1 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white text-sm font-medium rounded-lg transition-colors"
                      >
                        📋 Copy All
                      </button>
                      <button
                        onClick={downloadRecoveryCodes}
                        className="flex-1 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white text-sm font-medium rounded-lg transition-colors"
                      >
                        💾 Download
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Verification Form */}
          <form onSubmit={handleVerify} className="space-y-6">
            <div>
              <label htmlFor="totpCode" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Verification Code
              </label>
              <input
                type="text"
                id="totpCode"
                value={totpCode}
                onChange={(e) => {
                  setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6));
                  setError('');
                }}
                required
                maxLength={6}
                pattern="\d{6}"
                className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-center text-xl font-mono tracking-widest transition-all"
                placeholder="000000"
                disabled={loading}
                autoComplete="off"
              />
              <p className="mt-2 text-xs text-gray-500 dark:text-gray-400 text-center">
                Enter the 6-digit code from your authenticator app
              </p>
            </div>

            {error && (
              <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || totpCode.length !== 6}
              className="w-full py-3 px-4 bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Verifying...
                </span>
              ) : (
                'Complete 2FA Reset'
              )}
            </button>
          </form>

          <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
            <p className="text-xs text-blue-800 dark:text-blue-300">
              <strong>🔒 Security:</strong> Your old recovery codes have been invalidated. Make sure to save the new ones shown above.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
