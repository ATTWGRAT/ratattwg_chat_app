import { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import Register from './components/Register';
import Login from './components/Login';
import RecoveryLogin from './components/RecoveryLogin';
import TwoFAVerification from './components/TwoFAVerification';
import TwoFAReset from './components/TwoFAReset';
import Chat from './components/Chat';

function AppContent() {
  const { isAuthenticated, loading, user } = useAuth();
  const [view, setView] = useState('login'); // 'login', 'register', '2fa', 'recovery'
  const [registrationData, setRegistrationData] = useState(null);
  const [showResetFlow, setShowResetFlow] = useState(false);

  // Check if user needs to reset 2FA
  useEffect(() => {
    if (isAuthenticated && user && user.requires_2fa_reset) {
      setShowResetFlow(true);
    } else {
      setShowResetFlow(false);
    }
  }, [isAuthenticated, user]);

  // Reset to login view when user logs out
  useEffect(() => {
    if (!isAuthenticated && !loading) {
      setView('login');
      setRegistrationData(null);
    }
  }, [isAuthenticated, loading]);

  const handleRegistrationSuccess = (data) => {
    setRegistrationData(data);
    setView('2fa');
  };

  const handleBack = () => {
    setRegistrationData(null);
    setView('register');
  };

  const handleResetComplete = () => {
    setShowResetFlow(false);
    // Refresh the page to reload user data
    window.location.reload();
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <svg className="animate-spin h-12 w-12 text-blue-600 dark:text-blue-400 mx-auto mb-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p className="text-gray-600 dark:text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  if (isAuthenticated) {
    // If user needs to reset 2FA, show reset flow instead of chat
    if (showResetFlow) {
      return <TwoFAReset onResetComplete={handleResetComplete} />;
    }
    return <Chat />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-6xl">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-600 to-purple-700 rounded-2xl shadow-2xl mb-4 transform hover:scale-105 transition-transform">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-white mb-2">
            Secure Chat
          </h1>
          <p className="text-lg text-gray-600 dark:text-gray-400">
            End-to-end encrypted messaging with zero-knowledge architecture
          </p>
        </div>

        {/* Main Content */}
        <div className="flex justify-center">
          {view === 'login' && (
            <Login 
              onSwitchToRegister={() => setView('register')}
              onSwitchToRecovery={() => setView('recovery')}
            />
          )}
          
          {view === 'register' && (
            <Register 
              onSuccess={handleRegistrationSuccess}
              onSwitchToLogin={() => setView('login')}
            />
          )}
          
          {view === 'recovery' && (
            <RecoveryLogin 
              onBackToLogin={() => setView('login')}
            />
          )}
          
          {view === '2fa' && registrationData && (
            <TwoFAVerification 
              registrationData={registrationData}
              onBack={handleBack}
            />
          )}
        </div>

        {/* Footer */}
        <div className="mt-12 text-center">
          <p className="text-sm text-gray-500 dark:text-gray-500">
            Powered by Ed25519 signatures, Argon2id hashing, and AES-256 encryption
          </p>
        </div>
      </div>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
