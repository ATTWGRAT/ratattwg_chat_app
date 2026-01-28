"""Thread-safe session manager for tracking active WebSocket connections."""

import threading
from typing import Set, Dict


class SessionManager:
    """
    Thread-safe manager for tracking active user WebSocket sessions.
    
    Replaces the global active_user_sessions dictionary with a thread-safe
    implementation using locks to prevent race conditions.
    """
    
    def __init__(self):
        """Initialize the session manager with empty tracking dict and lock."""
        self._sessions: Dict[int, Set[str]] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested calls
    
    def add_session(self, user_id: int, session_id: str) -> int:
        """
        Add a session for a user.
        
        Args:
            user_id: ID of the user
            session_id: Socket.IO session ID
            
        Returns:
            int: Total number of sessions for this user
        """
        with self._lock:
            if user_id not in self._sessions:
                self._sessions[user_id] = set()
            self._sessions[user_id].add(session_id)
            return len(self._sessions[user_id])
    
    def remove_session(self, user_id: int, session_id: str) -> int:
        """
        Remove a session for a user.
        
        Args:
            user_id: ID of the user
            session_id: Socket.IO session ID
            
        Returns:
            int: Remaining number of sessions for this user
        """
        with self._lock:
            if user_id in self._sessions:
                self._sessions[user_id].discard(session_id)
                remaining = len(self._sessions[user_id])
                
                # Clean up empty sets
                if remaining == 0:
                    del self._sessions[user_id]
                
                return remaining
            return 0
    
    def get_sessions(self, user_id: int) -> Set[str]:
        """
        Get all session IDs for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            set: Set of session IDs (empty set if user has no sessions)
        """
        with self._lock:
            return self._sessions.get(user_id, set()).copy()
    
    def has_sessions(self, user_id: int) -> bool:
        """
        Check if a user has any active sessions.
        
        Args:
            user_id: ID of the user
            
        Returns:
            bool: True if user has at least one active session
        """
        with self._lock:
            return user_id in self._sessions and len(self._sessions[user_id]) > 0
    
    def session_count(self, user_id: int) -> int:
        """
        Get the number of active sessions for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            int: Number of active sessions
        """
        with self._lock:
            return len(self._sessions.get(user_id, set()))
    
    def clear_user_sessions(self, user_id: int) -> Set[str]:
        """
        Remove all sessions for a user and return them.
        
        Args:
            user_id: ID of the user
            
        Returns:
            set: Set of session IDs that were removed
        """
        with self._lock:
            sessions = self._sessions.get(user_id, set()).copy()
            if user_id in self._sessions:
                del self._sessions[user_id]
            return sessions
    
    def get_all_users(self) -> Set[int]:
        """
        Get all user IDs with active sessions.
        
        Returns:
            set: Set of user IDs
        """
        with self._lock:
            return set(self._sessions.keys())
    
    def total_sessions(self) -> int:
        """
        Get total number of active sessions across all users.
        
        Returns:
            int: Total number of sessions
        """
        with self._lock:
            return sum(len(sessions) for sessions in self._sessions.values())
    
    def clear_all(self) -> None:
        """Clear all sessions (useful for testing or shutdown)."""
        with self._lock:
            self._sessions.clear()
