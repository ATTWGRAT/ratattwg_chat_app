/**
 * API client for secure chat application
 * Handles all backend communication with signature verification
 */

import { createSignedRequest } from './crypto';

// Use environment variable or default to localhost
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

/**
 * Get encrypted private key for a user by email
 * @param {string} email 
 * @returns {Promise<Object>} Encrypted private key and IV
 */
export async function getEncryptedKey(email) {
  const response = await fetch(`${API_BASE_URL}/get-encrypted-key`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email })
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to get encrypted key');
  }
  
  return responseData;
}

/**
 * Register a new user
 * @param {Object} userData - {username, email, password_hash, encrypted_private_key, public_key, encryption_iv}
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Object>} Response with QR code and 2FA secret
 */
export async function register(userData, privateKey) {
  const signedRequest = createSignedRequest(userData, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include', // Include cookies for session
    body: JSON.stringify(signedRequest)
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.error || 'Registration failed');
  }
  
  return data;
}

/**
 * Verify 2FA code and complete registration
 * @param {string} totpCode - 6-digit TOTP code
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Object>} Response with user data
 */
export async function verify2FA(totpCode, privateKey) {
  const data = { totp_code: totpCode };
  const signedRequest = createSignedRequest(data, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/register/verify-2fa`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || '2FA verification failed');
  }
  
  return responseData;
}

/**
 * Login user
 * @param {string} email - User's email address
 * @param {string} passwordHash 
 * @param {string} totpCode 
 * @returns {Promise<Object>} Response with user data including encrypted private key
 */
export async function login(email, passwordHash, totpCode) {
  const response = await fetch(`${API_BASE_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify({
      email: email,
      password_hash: passwordHash,
      totp_code: totpCode
    })
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Login failed');
  }
  
  return responseData;
}

/**
 * Logout current user
 * @param {Uint8Array} privateKey 
 * @returns {Promise<Object>}
 */
export async function logout(privateKey) {
  const data = {};
  const signedRequest = createSignedRequest(data, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/logout`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Logout failed');
  }
  
  return responseData;
}

/**
 * Get current user info
 * @param {Uint8Array} privateKey 
 * @returns {Promise<Object>} User data
 */
export async function getCurrentUser(privateKey) {
  const data = {};
  const signedRequest = createSignedRequest(data, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/me`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to get user info');
  }
  
  return responseData;
}

/**
 * Check API health
 * @returns {Promise<Object>}
 */
export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL.replace('/api', '')}/health`);
  return await response.json();
}

// ============================================================================
// FRIEND REQUEST API FUNCTIONS
// ============================================================================

/**
 * Get all users for client-side filtering
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Array>} Array of users with id, username, public_key
 */
export async function searchUsers(privateKey) {
  const data = {}; // No search term needed, backend returns all users
  const signedRequest = createSignedRequest(data, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/search`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to get users');
  }
  
  return responseData.users;
}

/**
 * Send friend request to another user
 * @param {Object} requestData - {receiver_username, conversation_key_encrypted_for_receiver, conversation_key_encrypted_for_sender, sender_iv, signature_for_receiver}
 * @param {Uint8Array} privateKey - Private key for signing the request
 * @returns {Promise<Object>} Response with request_id
 */
export async function sendFriendRequest(requestData, privateKey) {
  const signedRequest = createSignedRequest(requestData, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/request/send`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to send friend request');
  }
  
  return responseData;
}

/**
 * Get pending friend requests (received)
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Array>} Array of pending requests
 */
export async function getPendingFriendRequests(privateKey) {
  const signedRequest = createSignedRequest({}, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/pending`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature-Data': JSON.stringify(signedRequest)
    },
    credentials: 'include'
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to get pending requests');
  }
  
  return response.json();
}

/**
 * Get sent friend requests (outgoing)
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Array>} List of sent friend requests
 */
export async function getSentFriendRequests(privateKey) {
  const signedRequest = createSignedRequest({}, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/sent`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature-Data': JSON.stringify(signedRequest)
    },
    credentials: 'include'
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to get sent requests');
  }

  return response.json();
}

/**
 * Accept friend request
 * @param {Object} acceptData - {request_id, conversation_key_encrypted_for_receiver, receiver_iv}
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Object>} Response with conversation_id
 */
export async function acceptFriendRequest(acceptData, privateKey) {
  const signedRequest = createSignedRequest(acceptData, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/request/accept`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to accept friend request');
  }
  
  return responseData;
}

/**
 * Reject friend request
 * @param {number} requestId - Friend request ID
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Object>} Response
 */
export async function rejectFriendRequest(requestId, privateKey) {
  const data = { request_id: requestId };
  const signedRequest = createSignedRequest(data, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/request/reject`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to reject friend request');
  }
  
  return responseData;
}

/**
 * Get list of friends
 * @param {Uint8Array} privateKey - Private key for signing
 * @returns {Promise<Array>} Array of friends
 */
export async function getFriendsList(privateKey) {
  const data = {};
  const signedRequest = createSignedRequest(data, privateKey);
  
  const response = await fetch(`${API_BASE_URL}/friends/list`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
    body: JSON.stringify(signedRequest)
  });
  
  const responseData = await response.json();
  
  if (!response.ok) {
    throw new Error(responseData.error || 'Failed to get friends list');
  }
  
  return responseData.friends;
}
