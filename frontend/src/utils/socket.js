/**
 * WebSocket connection management for real-time friend request updates
 */

import { io } from 'socket.io-client';

const SOCKET_URL = import.meta.env.VITE_API_URL?.replace('/api', '') || 'http://localhost:5000';

// Store socket in window to survive HMR (Hot Module Replacement)
if (!window.__socket) {
  window.__socket = null;
}
if (!window.__isInitializing) {
  window.__isInitializing = false;
}

/**
 * Initialize WebSocket connection (singleton pattern)
 * Uses cookies for session authentication
 */
export function initializeSocket() {
  // Return existing socket if already created
  if (window.__socket) {
    return window.__socket;
  }
  
  // Prevent multiple simultaneous initializations
  if (window.__isInitializing) {
    return window.__socket;
  }

  window.__isInitializing = true;
  
  window.__socket = io(SOCKET_URL, {
    withCredentials: true, // Send cookies for session auth
    transports: ['websocket', 'polling'], // Try WebSocket first, fall back to polling
    autoConnect: true,
    reconnection: true, // Enable auto-reconnection
    reconnectionDelay: 1000,
    reconnectionAttempts: 5,
    timeout: 10000,
    upgrade: true // Allow upgrading transport
  });

  window.__socket.on('connect', () => {
    window.__isInitializing = false;
  });

  window.__socket.on('disconnect', () => {
    window.__isInitializing = false;
  });

  window.__socket.on('connect_error', (error) => {
    console.error('[Socket] Connection error:', error.message);
    window.__isInitializing = false;
  });

  return window.__socket;
}

/**
 * Disconnect WebSocket and prevent reconnection
 */
export function disconnectSocket() {
  if (window.__socket) {
    // Remove all listeners first to prevent any callbacks
    window.__socket.removeAllListeners();
    // Close the connection completely (prevents auto-reconnect attempts)
    window.__socket.close();
    window.__socket = null;
    window.__isInitializing = false;
  }
}

/**
 * Get current socket instance
 */
export function getSocket() {
  return window.__socket;
}

/**
 * Listen for new friend requests
 * @param {Function} callback - Called when a new friend request is received
 */
export function onFriendRequestReceived(callback) {
  if (!window.__socket) return;
  // Remove any existing listener first to prevent duplicates
  window.__socket.off('friend_request_received');
  window.__socket.on('friend_request_received', callback);
}

/**
 * Listen for new user registrations
 * @param {Function} callback - Called when a new user registers
 */
export function onUserRegistered(callback) {
  if (!window.__socket) return;
  // Remove any existing listener first to prevent duplicates
  window.__socket.off('user_registered');
  window.__socket.on('user_registered', callback);
}

/**
 * Listen for accepted friend requests
 * @param {Function} callback - Called when someone accepts your friend request
 */
export function onFriendRequestAccepted(callback) {
  if (!window.__socket) return;
  // Remove any existing listener first to prevent duplicates
  window.__socket.off('friend_request_accepted');
  window.__socket.on('friend_request_accepted', callback);
}

/**
 * Listen for rejected friend requests
 * @param {Function} callback - Called when someone rejects your friend request
 */
export function onFriendRequestRejected(callback) {
  if (!window.__socket) return;
  // Remove any existing listener first to prevent duplicates
  window.__socket.off('friend_request_rejected');
  window.__socket.on('friend_request_rejected', callback);
}

/**
 * Listen for friend removal
 * @param {Function} callback - Called when a friend removes you or you remove them
 */
export function onFriendRemoved(callback) {
  if (!window.__socket) return;
  // Remove any existing listener first to prevent duplicates
  window.__socket.off('friend_removed');
  window.__socket.on('friend_removed', callback);
}

/**
 * Listen for new messages
 * @param {Function} callback - Called with {conversation_id, message}
 */
export function onMessageReceived(callback) {
  if (!window.__socket) return;
  
  window.__socket.off('message_received');
  window.__socket.on('message_received', callback);
}

/**
 * Listen for message deletions
 * @param {Function} callback - Called with {conversation_id, message_id}
 */
export function onMessageDeleted(callback) {
  if (!window.__socket) return;
  
  window.__socket.off('message_deleted');
  window.__socket.on('message_deleted', callback);
}

/**
 * Listen for message read receipts
 * @param {Function} callback - Called with {conversation_id, message_ids, reader_id}
 */
export function onMessagesRead(callback) {
  if (!window.__socket) return;
  
  window.__socket.off('messages_read');
  window.__socket.on('messages_read', callback);
}

/**
 * Remove all event listeners
 */
export function removeAllListeners() {
  if (!window.__socket) return;
  window.__socket.off('friend_request_received');
  window.__socket.off('friend_request_accepted');
  window.__socket.off('friend_request_rejected');
  window.__socket.off('friend_removed');
  window.__socket.off('message_received');
  window.__socket.off('message_deleted');
  window.__socket.off('messages_read');
  window.__socket.off('force_logout');
}

/**
 * Listen for force logout event (when user logs in from another location)
 * @param {Function} callback - Called when user is forcibly logged out
 */
export function onForceLogout(callback) {
  if (!window.__socket) return;
  
  window.__socket.off('force_logout');
  window.__socket.on('force_logout', callback);
}
