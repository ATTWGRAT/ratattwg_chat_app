/**
 * Custom hook for WebSocket connection management
 */

import { useEffect, useRef } from 'react';
import {
  onFriendRequestReceived,
  onFriendRequestAccepted,
  onFriendRequestRejected,
  onFriendRemoved,
  onMessageReceived
} from '../utils/socket';

export function useWebSocket(privateKey, callbacks = {}) {
  const callbacksRef = useRef(callbacks);

  // Update callbacks ref when they change
  useEffect(() => {
    callbacksRef.current = callbacks;
  }, [callbacks]);

  useEffect(() => {
    if (!privateKey) return;

    // Set up event listeners
    if (callbacksRef.current.onFriendRequestReceived) {
      onFriendRequestReceived(callbacksRef.current.onFriendRequestReceived);
    }
    if (callbacksRef.current.onFriendRequestAccepted) {
      onFriendRequestAccepted(callbacksRef.current.onFriendRequestAccepted);
    }
    if (callbacksRef.current.onFriendRequestRejected) {
      onFriendRequestRejected(callbacksRef.current.onFriendRequestRejected);
    }
    if (callbacksRef.current.onFriendRemoved) {
      onFriendRemoved(callbacksRef.current.onFriendRemoved);
    }
    if (callbacksRef.current.onMessageReceived) {
      onMessageReceived(callbacksRef.current.onMessageReceived);
    }

    return () => {
      // Don't disconnect socket here - it's managed by AuthContext
      // Just remove listeners if needed (handled by component lifecycle)
    };
  }, [privateKey]);
}
