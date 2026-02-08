"""
Rate Limiter - Security Component K
Provides rate limiting decorators and utilities
"""

import time
import inspect
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Dict, Optional

from fastapi import HTTPException, Request, status


class RateLimiter:
    """
    In-memory rate limiter for API endpoints.
    
    Note: In production, use Redis or similar distributed cache
    for rate limiting across multiple server instances.
    """
    
    def __init__(self):
        # Structure: {key: [(timestamp, count)]}
        self._requests: Dict[str, list] = defaultdict(list)
        self._cleanup_interval = 300  # Clean up every 5 minutes
        self._last_cleanup = time.time()
    
    def _cleanup_old_entries(self):
        """Remove entries older than 1 hour."""
        current_time = time.time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        cutoff_time = current_time - 3600
        for key in list(self._requests.keys()):
            self._requests[key] = [
                (ts, count) for ts, count in self._requests[key]
                if ts > cutoff_time
            ]
            if not self._requests[key]:
                del self._requests[key]
        
        self._last_cleanup = current_time
    
    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> tuple[bool, Optional[int]]:
        """
        Check if request is allowed under rate limit.
        
        Args:
            key: Unique identifier (e.g., user_id, IP address)
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        self._cleanup_old_entries()
        
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        # Filter requests within the time window
        recent_requests = [
            (ts, count) for ts, count in self._requests[key]
            if ts > cutoff_time
        ]
        
        # Count total requests in window
        total_requests = sum(count for _, count in recent_requests)
        
        if total_requests >= max_requests:
            # Calculate retry_after based on oldest request
            if recent_requests:
                oldest_request_time = min(ts for ts, _ in recent_requests)
                retry_after = int(oldest_request_time + window_seconds - current_time)
                return False, max(retry_after, 1)
            return False, window_seconds
        
        # Allow request and record it
        self._requests[key] = recent_requests + [(current_time, 1)]
        return True, None
    
    def reset(self, key: str):
        """Reset rate limit for a specific key."""
        if key in self._requests:
            del self._requests[key]


# Global rate limiter instance
_rate_limiter = RateLimiter()


def rate_limit(max_calls: int, period_seconds: int = 60, key_func: Optional[Callable] = None):
    """
    Rate limiting decorator for FastAPI endpoints.
    
    Args:
        max_calls: Maximum number of calls allowed
        period_seconds: Time period in seconds
        key_func: Optional function to generate rate limit key from request
                 Default: uses client IP address
    
    Example:
        @rate_limit(max_calls=5, period_seconds=60)
        async def my_endpoint(request: Request):
            ...
    """
    def decorator(func):
        is_async = inspect.iscoroutinefunction(func)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get('request')
            
            if not request:
                # No request object, skip rate limiting
                return await func(*args, **kwargs)
            
            # Generate rate limit key
            if key_func:
                key = key_func(request)
            else:
                # Default: use client IP
                key = f"ip:{request.client.host}"
            
            # Check rate limit
            allowed, retry_after = _rate_limiter.is_allowed(
                key, max_calls, period_seconds
            )
            
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)}
                )
            
            if is_async:
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter
