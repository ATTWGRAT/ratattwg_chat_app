/**
 * 2FA Verification component
 * Displays QR code and allows user to verify TOTP code
 */

import { useState } from 'react';
import { verify2FA } from '../utils/api';
import { useAuth } from '../context/AuthContext';

export default function TwoFAVerification({ registrationData, onBack }) {
  const [totpCode, setTotpCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showRecoveryCodes, setShowRecoveryCodes] = useState(true);
  const [recoveryCodesCopied, setRecoveryCodesCopied] = useState(false);
  const { completeRegistration } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!totpCode || totpCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Verify 2FA code with signed request
      const response = await verify2FA(totpCode, registrationData.privateKey);

      // Complete registration and store private key + Master Key in memory
      completeRegistration(response.user, registrationData.privateKey, registrationData.masterKey);

    } catch (error) {
      console.error('2FA verification error:', error);
      setError(error.message || 'Invalid verification code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleCodeChange = (e) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
    setTotpCode(value);
    setError('');
  };

  const copyRecoveryCodes = () => {
    const codes = registrationData.recovery_codes.join('\n');
    navigator.clipboard.writeText(codes).then(() => {
      setRecoveryCodesCopied(true);
      setTimeout(() => setRecoveryCodesCopied(false), 3000);
    });
  };

  const downloadRecoveryCodes = () => {
    const codes = registrationData.recovery_codes.join('\n');
    const blob = new Blob([`Secure Chat - Recovery Codes\n\nGenerated: ${new Date().toLocaleString()}\n\nIMPORTANT: Store these codes in a secure location.\nEach code can only be used once.\n\n${codes}\n\n⚠️ Keep these codes secret and secure!`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'secure-chat-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="w-full max-w-md">
      <div className="bg-white dark:bg-gray-800 shadow-2xl rounded-2xl p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-green-500 to-teal-600 rounded-full mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white">Setup 2FA</h2>
          <p className="mt-2 text-gray-600 dark:text-gray-400">Scan the QR code with your authenticator app</p>
        </div>

        <div className="space-y-6">
          {/* QR Code */}
          <div className="bg-white dark:bg-gray-700 p-6 rounded-xl border-2 border-gray-200 dark:border-gray-600">
            <div className="flex justify-center mb-4">
              <img 
                src={registrationData.qr_code} 
                alt="2FA QR Code"
                className="w-64 h-64 border-4 border-white dark:border-gray-600 rounded-lg shadow-md"
              />
            </div>
            
            <div className="text-center">
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Or enter this code manually:
              </p>
              <code className="inline-block px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg text-sm font-mono border border-gray-300 dark:border-gray-600">
                {registrationData.secret}
              </code>
            </div>
          </div>

          {/* Instructions */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-blue-900 dark:text-blue-300 mb-2">
              📱 How to setup:
            </h3>
            <ol className="text-xs text-blue-800 dark:text-blue-300 space-y-1 list-decimal list-inside">
              <li>Open your authenticator app (Google Authenticator, Authy, etc.)</li>
              <li>Scan the QR code or enter the code manually</li>
              <li>Enter the 6-digit code shown in your app below</li>
            </ol>
          </div>

          {/* Recovery Codes Section */}
          {registrationData.recovery_codes && registrationData.recovery_codes.length > 0 && (
            <div className="bg-gradient-to-br from-orange-50 to-red-50 dark:from-orange-900/20 dark:to-red-900/20 border-2 border-orange-300 dark:border-orange-700 rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="text-sm font-bold text-orange-900 dark:text-orange-300 flex items-center gap-2">
                    <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                    </svg>
                    Recovery Codes
                  </h3>
                  <p className="text-xs text-orange-800 dark:text-orange-300 mt-1">
                    Save these codes now! They can only be used once each.
                  </p>
                </div>
                <button
                  onClick={() => setShowRecoveryCodes(!showRecoveryCodes)}
                  className="text-orange-600 dark:text-orange-400 hover:text-orange-800 dark:hover:text-orange-200"
                >
                  <svg className={`w-5 h-5 transform transition-transform ${showRecoveryCodes ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              </div>

              {showRecoveryCodes && (
                <>
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 mb-3 max-h-48 overflow-y-auto">
                    <div className="grid grid-cols-2 gap-2">
                      {registrationData.recovery_codes.map((code, idx) => (
                        <div key={idx} className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-700 rounded border border-gray-200 dark:border-gray-600">
                          <span className="text-xs font-semibold text-gray-500 dark:text-gray-400 w-4">
                            {idx + 1}.
                          </span>
                          <code className="text-sm font-mono text-gray-900 dark:text-white">
                            {code}
                          </code>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={copyRecoveryCodes}
                      className="flex-1 px-3 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      {recoveryCodesCopied ? (
                        <>
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                          Copied!
                        </>
                      ) : (
                        <>
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                          Copy Codes
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={downloadRecoveryCodes}
                      className="flex-1 px-3 py-2 bg-orange-600 hover:bg-orange-700 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                      Download
                    </button>
                  </div>

                  <div className="mt-3 p-3 bg-red-100 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-lg">
                    <p className="text-xs text-red-800 dark:text-red-300 font-medium">
                      ⚠️ <strong>CRITICAL:</strong> These codes will NOT be shown again! Save them in a password manager or secure location before continuing.
                    </p>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Verification Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="totpCode" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Verification Code
              </label>
              <input
                type="text"
                id="totpCode"
                value={totpCode}
                onChange={handleCodeChange}
                required
                maxLength={6}
                pattern="\d{6}"
                className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 text-center text-2xl font-mono tracking-widest transition-all"
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

            <div className="flex gap-3">
              <button
                type="button"
                onClick={onBack}
                disabled={loading}
                className="flex-1 py-3 px-4 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 font-semibold rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Back
              </button>
              
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="flex-1 py-3 px-4 bg-gradient-to-r from-green-500 to-teal-600 hover:from-green-600 hover:to-teal-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
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
                  'Verify & Complete'
                )}
              </button>
            </div>
          </form>

          {/* Security Notice */}
          <div className="mt-6 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
            <p className="text-xs text-green-800 dark:text-green-300">
              <strong>🔒 Security Tip:</strong> Store your recovery codes in a password manager or write them down and keep them in a secure physical location. You'll need them if you lose your phone or authenticator app.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
