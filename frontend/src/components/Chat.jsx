/**
 * Chat component with Friends sidebar
 */

import { useState, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import Friends from './Friends';
import Conversation from './Conversation';

export default function Chat() {
  const { user, privateKey, masterKey, logout } = useAuth();
  const [selectedConversation, setSelectedConversation] = useState(null);
  const [selectedFriend, setSelectedFriend] = useState(null);
  const [showFriends, setShowFriends] = useState(true);

  const handleLogout = useCallback(async () => {
    await logout();
  }, [logout]);

  const handleSelectConversation = useCallback((conversationId, friend) => {
    setSelectedConversation(conversationId);
    setSelectedFriend(friend);
    // Hide friends on mobile when conversation is selected
    if (window.innerWidth < 1024) {
      setShowFriends(false);
    }
  }, []);

  const handleBackToFriends = useCallback(() => {
    setSelectedConversation(null);
    setSelectedFriend(null);
    setShowFriends(true);
  }, []);

  const handleConversationClosed = useCallback((conversationId) => {
    // Close conversation if it's currently open
    if (selectedConversation === conversationId) {
      setSelectedConversation(null);
      setSelectedFriend(null);
      setShowFriends(true);
    }
  }, [selectedConversation]);

  const toggleFriendsSidebar = useCallback(() => {
    setShowFriends(prev => !prev);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
      <div className="container mx-auto px-4 py-8 h-screen flex flex-col">
        {/* Header */}
        <div className="bg-white dark:bg-gray-800 shadow-xl rounded-2xl p-6 mb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={toggleFriendsSidebar}
                className="lg:hidden p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                aria-label="Toggle sidebar"
              >
                <svg className="w-6 h-6 text-gray-600 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              <div>
                <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                  Secure Chat
                </h1>
                <p className="text-gray-600 dark:text-gray-400 flex items-center gap-2">
                  Welcome back, <span className="font-semibold text-blue-600 dark:text-blue-400">{user?.username}</span>
                </p>
              </div>
            </div>
            
            <button
              onClick={handleLogout}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors flex items-center"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              Logout
            </button>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="flex-1 flex gap-4 overflow-hidden">
          {/* Friends Sidebar */}
          <div className={`${showFriends ? 'block' : 'hidden'} lg:block w-full lg:w-96 bg-white dark:bg-gray-800 shadow-xl rounded-2xl overflow-hidden`}>
            <Friends 
              privateKey={privateKey} 
              masterKey={masterKey}
              username={user?.username}
              onSelectConversation={handleSelectConversation}
              onConversationClosed={handleConversationClosed}
            />
          </div>

          {/* Chat Area */}
          <div className="flex-1 bg-white dark:bg-gray-800 shadow-xl rounded-2xl overflow-hidden">
            {selectedConversation && selectedFriend ? (
              <Conversation
                conversationId={selectedConversation}
                friend={selectedFriend}
                userId={user?.id}
                privateKey={privateKey}
                masterKey={masterKey}
                onBack={handleBackToFriends}
              />
            ) : (
              <div className="h-full flex items-center justify-center p-8">
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-24 h-24 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full mb-6">
                    <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                    </svg>
                  </div>
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                    Select a Conversation
                  </h2>
                  <p className="text-gray-600 dark:text-gray-400">
                    Choose a friend from the sidebar to start messaging securely!
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
