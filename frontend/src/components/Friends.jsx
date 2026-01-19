/**
 * Friends component - Search users, send/manage friend requests
 */

import { useState, useEffect } from 'react';
import {
  searchUsers,
  sendFriendRequest,
  getPendingFriendRequests,
  getSentFriendRequests,
  acceptFriendRequest,
  rejectFriendRequest,
  getFriendsList
} from '../utils/api';
import {
  generateConversationKey,
  encryptWithPublicKey,
  encryptConversationKey,
  decryptWithPrivateKey,
  createSignatureForReceiver,
  verifySignature,
  importPublicKeyFromPEM,
  bytesToHex
} from '../utils/crypto';

export default function Friends({ privateKey, masterKey, username, onSelectConversation }) {
  const [activeTab, setActiveTab] = useState('search'); // search, pending, friends
  const [searchTerm, setSearchTerm] = useState('');
  const [allUsers, setAllUsers] = useState([]); // All users for filtering
  const [searchResults, setSearchResults] = useState([]);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [sentRequests, setSentRequests] = useState([]); // Outgoing pending requests
  const [friendsList, setFriendsList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [selectedRequest, setSelectedRequest] = useState(null); // For modal
  const [showKeyData, setShowKeyData] = useState(false); // Toggle key visibility
  const [decryptedKey, setDecryptedKey] = useState(null); // Decrypted conversation key

  // Load pending requests, friends, and all users on mount
  useEffect(() => {
    loadPendingRequests();
    loadSentRequests();
    loadFriendsList();
    loadAllUsers();
  }, []);

  // Poll for updates every 15 seconds
  useEffect(() => {
    const pollInterval = setInterval(() => {
      loadPendingRequests();
      loadSentRequests();
      loadFriendsList();
      loadAllUsers(); // Also reload users to detect rejected requests
    }, 15000); // Poll every 15 seconds

    return () => clearInterval(pollInterval);
  }, [privateKey]);

  // Filter users client-side as user types
  useEffect(() => {
    if (searchTerm.length < 1) {
      setSearchResults([]);
      return;
    }

    // Get IDs of users who are already friends
    const friendIds = new Set(friendsList.map(friend => friend.id));
    
    // Get IDs of users with pending sent requests
    const sentRequestIds = new Set(sentRequests.map(req => req.receiver.id));
    
    const filtered = allUsers.filter(user => 
      user.username.toLowerCase().includes(searchTerm.toLowerCase()) &&
      !friendIds.has(user.id) && // Exclude existing friends
      !sentRequestIds.has(user.id) // Exclude users with pending requests
    );
    setSearchResults(filtered);
  }, [searchTerm, allUsers, friendsList, sentRequests]);

  const loadAllUsers = async () => {
    try {
      setLoading(true);
      const users = await searchUsers(privateKey);
      setAllUsers(users);
    } catch (err) {
      console.error('Failed to load users:', err);
      setError(err.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const loadPendingRequests = async () => {
    try {
      const requests = await getPendingFriendRequests(privateKey);
      setPendingRequests(requests);
    } catch (err) {
      console.error('Failed to load pending requests:', err);
    }
  };

  const loadSentRequests = async () => {
    try {
      const requests = await getSentFriendRequests(privateKey);
      setSentRequests(requests);
    } catch (err) {
      console.error('Failed to load sent requests:', err);
    }
  };

  const loadFriendsList = async () => {
    try {
      const friends = await getFriendsList(privateKey);
      setFriendsList(friends);
    } catch (err) {
      console.error('Failed to load friends list:', err);
    }
  };

  const handleSendFriendRequest = async (user) => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      // 1. Generate random conversation key (32 bytes)
      const conversationKey = generateConversationKey();

      // 2. Encrypt conversation key with recipient's public key
      const conversationKeyEncryptedForReceiver = await encryptWithPublicKey(
        conversationKey,
        user.public_key
      );

      // 3. Encrypt conversation key with sender's Master Key
      const { encrypted, iv } = await encryptConversationKey(conversationKey, masterKey);

      // 4. Create signature for receiver (without sender's key in data)
      const dataToSign = {
        receiver_username: user.username,
        conversation_key_encrypted_for_receiver: conversationKeyEncryptedForReceiver
      };
      const signatureForReceiver = createSignatureForReceiver(privateKey, dataToSign);

      // 5. Send friend request
      const requestData = {
        receiver_username: user.username,
        conversation_key_encrypted_for_receiver: conversationKeyEncryptedForReceiver,
        conversation_key_encrypted_for_sender: encrypted,
        sender_iv: iv,
        signature_for_receiver: signatureForReceiver
      };

      await sendFriendRequest(requestData, privateKey);
      setSuccess(`Friend request sent to ${user.username}!`);
      
      // Reload sent requests to update the UI
      await loadSentRequests();
    } catch (err) {
      setError(err.message || 'Failed to send friend request');
    } finally {
      setLoading(false);
    }
  };

  const handleAcceptRequest = async (request) => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      // 1. Verify signature from sender
      const senderPublicKeyBytes = importPublicKeyFromPEM(request.sender.public_key);
      
      // Reconstruct the data that was signed
      const dataToVerify = {
        receiver_username: username,
        conversation_key_encrypted_for_receiver: request.conversation_key_encrypted_for_receiver
      };
      
      const isValidSignature = verifySignature(
        senderPublicKeyBytes,
        dataToVerify,
        request.signature_for_receiver
      );
      
      if (!isValidSignature) {
        throw new Error('Invalid signature: This friend request may have been tampered with');
      }

      // 2. Decrypt conversation key using private key
      const conversationKey = await decryptWithPrivateKey(
        request.conversation_key_encrypted_for_receiver,
        privateKey
      );

      // 3. Re-encrypt conversation key with receiver's Master Key
      const { encrypted, iv } = await encryptConversationKey(conversationKey, masterKey);

      // 4. Accept the request
      const acceptData = {
        request_id: request.id,
        conversation_key_encrypted_for_receiver: encrypted,
        receiver_iv: iv
      };

      const response = await acceptFriendRequest(acceptData, privateKey);
      setSuccess(`Friend request from ${request.sender.username} accepted!`);
      
      // Update pending requests list immediately
      setPendingRequests(pendingRequests.filter(req => req.id !== request.id));
      
      // Reload friends list to show new friend
      await loadFriendsList();
      
      // Switch to friends tab to show the newly added friend
      setActiveTab('friends');
    } catch (err) {
      setError(err.message || 'Failed to accept friend request');
    } finally {
      setLoading(false);
    }
  };

  const handleRejectRequest = async (request) => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await rejectFriendRequest(request.id, privateKey);
      setSuccess(`Friend request from ${request.sender.username} rejected`);
      
      // Update pending requests list immediately
      setPendingRequests(pendingRequests.filter(req => req.id !== request.id));
      
      // Add the user back to the search pool since request is rejected
      await loadAllUsers();
    } catch (err) {
      setError(err.message || 'Failed to reject friend request');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-full flex flex-col bg-white dark:bg-gray-800">
      {/* Header with Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="flex space-x-1 p-2">
          <button
            onClick={() => setActiveTab('search')}
            className={`flex-1 py-2 px-4 rounded-lg font-medium transition-colors ${
              activeTab === 'search'
                ? 'bg-blue-500 text-white'
                : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
            }`}
          >
            <svg className="inline w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            Search
          </button>
          <button
            onClick={() => setActiveTab('pending')}
            className={`flex-1 py-2 px-4 rounded-lg font-medium transition-colors relative ${
              activeTab === 'pending'
                ? 'bg-blue-500 text-white'
                : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
            }`}
          >
            <svg className="inline w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Pending
            {pendingRequests.length > 0 && (
              <span className="absolute top-1 right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                {pendingRequests.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('friends')}
            className={`flex-1 py-2 px-4 rounded-lg font-medium transition-colors ${
              activeTab === 'friends'
                ? 'bg-blue-500 text-white'
                : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
            }`}
          >
            <svg className="inline w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
            Friends ({friendsList.length})
          </button>
        </div>
      </div>

      {/* Messages */}
      {(error || success) && (
        <div className="p-4">
          {error && (
            <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}
          {success && (
            <div className="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
              <p className="text-sm text-green-600 dark:text-green-400">{success}</p>
            </div>
          )}
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {/* Search Tab */}
        {activeTab === 'search' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by username..."
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
                disabled={loading}
              />
              {loading && (
                <div className="flex items-center px-3">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
                </div>
              )}
            </div>

            {searchResults.length > 0 ? (
              <div className="space-y-2">
                {searchResults.map(user => (
                  <div
                    key={user.id}
                    className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors"
                  >
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                        <span className="text-white font-bold text-lg">
                          {user.username.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">{user.username}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">User ID: {user.id}</p>
                      </div>
                    </div>
                    {sentRequests.some(req => req.receiver.id === user.id) ? (
                      <div className="px-4 py-2 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 font-medium rounded-lg border border-yellow-300 dark:border-yellow-700">
                        <svg className="inline w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Pending
                      </div>
                    ) : (
                      <button
                        onClick={() => handleSendFriendRequest(user)}
                        disabled={loading}
                        className="px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-medium rounded-lg transition-all disabled:opacity-50"
                      >
                        <svg className="inline w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Add Friend
                      </button>
                    )}
                  </div>
                ))}
              </div>
            ) : searchTerm && !loading ? (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <svg className="mx-auto w-16 h-16 mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p>No users found</p>
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <svg className="mx-auto w-16 h-16 mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <p>Search for users to add as friends</p>
              </div>
            )}
          </div>
        )}

        {/* Pending Requests Tab */}
        {activeTab === 'pending' && (
          <div className="space-y-3">
            {pendingRequests.length > 0 ? (
              pendingRequests.map(request => (
                <div
                  key={request.id}
                  className="p-4 bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 border border-blue-200 dark:border-blue-800 rounded-lg"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                        <span className="text-white font-bold text-xl">
                          {request.sender.username.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {request.sender.username}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {new Date(request.created_at).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={async () => {
                        setSelectedRequest(request);
                        setShowKeyData(false);
                        // Decrypt the conversation key for display
                        try {
                          const key = await decryptWithPrivateKey(
                            request.conversation_key_encrypted_for_receiver,
                            privateKey
                          );
                          setDecryptedKey(bytesToHex(key));
                        } catch (err) {
                          console.error('Failed to decrypt key:', err);
                          setDecryptedKey(null);
                        }
                      }}
                      className="px-3 py-1 text-sm text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg transition-colors"
                    >
                      View Details
                    </button>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleAcceptRequest(request)}
                      disabled={loading}
                      className="flex-1 px-4 py-2 bg-green-500 hover:bg-green-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                    >
                      <svg className="inline w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      Accept
                    </button>
                    <button
                      onClick={() => handleRejectRequest(request)}
                      disabled={loading}
                      className="flex-1 px-4 py-2 bg-red-500 hover:bg-red-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                    >
                      <svg className="inline w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                      Reject
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <svg className="mx-auto w-16 h-16 mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                </svg>
                <p>No pending friend requests</p>
              </div>
            )}
          </div>
        )}

        {/* Friends List Tab */}
        {activeTab === 'friends' && (
          <div className="space-y-2">
            {friendsList.length > 0 ? (
              friendsList.map(friend => (
                <div
                  key={friend.id}
                  onClick={() => onSelectConversation && onSelectConversation(friend.conversation_id)}
                  className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors cursor-pointer"
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                      <span className="text-white font-bold text-lg">
                        {friend.username.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">{friend.username}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Friends since {new Date(friend.friends_since).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              ))
            ) : (
              <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                <svg className="mx-auto w-16 h-16 mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
                <p>No friends yet</p>
                <p className="text-sm mt-2">Search for users and send friend requests!</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Friend Request Details Modal */}
      {selectedRequest && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              {/* Header */}
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white">
                  Friend Request Details
                </h3>
                <button
                  onClick={() => {
                    setSelectedRequest(null);
                    setShowKeyData(false);
                    setDecryptedKey(null);
                  }}
                  className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  <svg className="w-6 h-6 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Sender Info */}
              <div className="mb-6 p-4 bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                    <span className="text-white font-bold text-2xl">
                      {selectedRequest.sender.username.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <p className="text-lg font-semibold text-gray-900 dark:text-white">
                      {selectedRequest.sender.username}
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      Sent on {new Date(selectedRequest.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>

              {/* Key Data Section */}
              <div className="mb-6">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Encrypted Conversation Key
                  </h4>
                  <button
                    onClick={() => setShowKeyData(!showKeyData)}
                    className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    {showKeyData ? 'Hide Key' : 'Show Key'}
                  </button>
                </div>

                {showKeyData && (
                  <div className="space-y-4">
                    {decryptedKey ? (
                      <>
                        <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                          <p className="text-xs font-semibold text-gray-600 dark:text-gray-400 mb-2">
                            DECRYPTED CONVERSATION KEY (HEX):
                          </p>
                          <code className="block text-xs text-gray-800 dark:text-gray-200 break-all font-mono">
                            {decryptedKey}
                          </code>
                        </div>

                        <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                          <p className="text-xs font-semibold text-gray-600 dark:text-gray-400 mb-2">
                            SIGNATURE:
                          </p>
                          <code className="block text-xs text-gray-800 dark:text-gray-200 break-all font-mono">
                            {selectedRequest.signature_for_receiver}
                          </code>
                        </div>

                        <div className="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                          <p className="text-xs text-blue-800 dark:text-blue-200">
                            <svg className="inline w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            This is the shared conversation key that will be used to encrypt all messages in this conversation.
                          </p>
                        </div>
                      </>
                    ) : (
                      <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                        <p className="text-xs text-red-800 dark:text-red-200">
                          Failed to decrypt conversation key
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3">
                <button
                  onClick={() => {
                    handleAcceptRequest(selectedRequest);
                    setSelectedRequest(null);
                    setShowKeyData(false);
                    setDecryptedKey(null);
                  }}
                  disabled={loading}
                  className="flex-1 px-6 py-3 bg-green-500 hover:bg-green-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                >
                  <svg className="inline w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Accept Request
                </button>
                <button
                  onClick={() => {
                    handleRejectRequest(selectedRequest);
                    setSelectedRequest(null);
                    setShowKeyData(false);
                    setDecryptedKey(null);
                  }}
                  disabled={loading}
                  className="flex-1 px-6 py-3 bg-red-500 hover:bg-red-600 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                >
                  <svg className="inline w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  Reject Request
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
