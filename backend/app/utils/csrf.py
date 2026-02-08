"""CSRF protection utilities for API endpoints."""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request, status

# Store CSRF tokens in memory (in production, use Redis)
csrf_tokens: dict[str, datetime] = {}

# CSRF token expiry time (30 minutes)
CSRF_TOKEN_EXPIRY = timedelta(minutes=30)


def generate_csrf_token() -> str:
    """Generate a new CSRF token."""
    token = secrets.token_urlsafe(32)
    csrf_tokens[token] = datetime.utcnow()
    return token


def validate_csrf_token(token: Optional[str]) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: The CSRF token to validate
        
    Returns:
        True if token is valid, False otherwise
    """
    if not token:
        return False
    
    if token not in csrf_tokens:
        return False
    
    # Check if token has expired
    token_time = csrf_tokens[token]
    if datetime.utcnow() - token_time > CSRF_TOKEN_EXPIRY:
        # Remove expired token
        del csrf_tokens[token]
        return False
    
    return True


def cleanup_expired_tokens():
    """Remove expired CSRF tokens from storage."""
    current_time = datetime.utcnow()
    expired = [
        token for token, timestamp in csrf_tokens.items()
        if current_time - timestamp > CSRF_TOKEN_EXPIRY
    ]
    for token in expired:
        del csrf_tokens[token]


async def verify_csrf_token(request: Request) -> None:
    """
    Dependency to verify CSRF token from request headers.
    
    Raises:
        HTTPException: If CSRF token is missing or invalid
    """
    # Get CSRF token from header
    csrf_token = request.headers.get("X-CSRF-Token")
    
    if not validate_csrf_token(csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token"
        )
    
    # Clean up expired tokens periodically
    cleanup_expired_tokens()
