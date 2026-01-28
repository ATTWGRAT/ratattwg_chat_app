"""Helper utilities for common operations."""

from datetime import datetime, timezone


def is_valid_timestamp(timestamp: int, max_age_seconds: int = 300) -> bool:
    """
    Check if timestamp is within acceptable age.
    
    Args:
        timestamp: Unix timestamp to validate
        max_age_seconds: Maximum age in seconds (default 5 minutes)
        
    Returns:
        bool: True if timestamp is valid and recent
    """
    try:
        request_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        age = (now - request_time).total_seconds()
        
        # Check if timestamp is not from the future (with 60s tolerance)
        if age < -60:
            return False
            
        # Check if timestamp is not too old
        if age > max_age_seconds:
            return False
            
        return True
    except (ValueError, OSError, OverflowError):
        return False

