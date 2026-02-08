"""
Device fingerprinting utilities for tracking trusted devices.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional


def generate_device_fingerprint(user_agent: str, ip_address: str) -> str:
    """
    Generate a device fingerprint from user agent and IP address.
    
    Note: This is a basic implementation. In production, consider:
    - Canvas fingerprinting
    - WebGL fingerprinting
    - Audio fingerprinting
    - Screen resolution and timezone
    - Plugin enumeration
    
    Args:
        user_agent: HTTP User-Agent header
        ip_address: Client IP address
    
    Returns:
        str: SHA-256 hash of device characteristics
    """
    # Normalize user agent (remove version numbers for stability)
    normalized_ua = normalize_user_agent(user_agent)
    
    # Combine characteristics
    fingerprint_data = f"{normalized_ua}|{ip_address}"
    
    # Hash to create fingerprint
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()


def normalize_user_agent(user_agent: str) -> str:
    """
    Normalize user agent string to reduce version-specific variations.
    
    Args:
        user_agent: Raw user agent string
    
    Returns:
        str: Normalized user agent
    """
    if not user_agent:
        return "unknown"
    
    # Extract browser and OS (simple implementation)
    # In production, use user-agents library for better parsing
    ua_lower = user_agent.lower()
    
    # Detect browser
    if "chrome" in ua_lower and "edg" not in ua_lower:
        browser = "chrome"
    elif "firefox" in ua_lower:
        browser = "firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "safari"
    elif "edg" in ua_lower:
        browser = "edge"
    else:
        browser = "other"
    
    # Detect OS
    if "windows" in ua_lower:
        os = "windows"
    elif "mac" in ua_lower or "darwin" in ua_lower:
        os = "macos"
    elif "linux" in ua_lower:
        os = "linux"
    elif "android" in ua_lower:
        os = "android"
    elif "ios" in ua_lower or "iphone" in ua_lower or "ipad" in ua_lower:
        os = "ios"
    else:
        os = "other"
    
    return f"{browser}_{os}"


def generate_device_auth_token() -> str:
    """
    Generate a secure random token for device authorization.
    
    Returns:
        str: 32-character hexadecimal token
    """
    return secrets.token_hex(16)


def get_token_expiry(hours: int = 24) -> datetime:
    """
    Get expiry time for device authorization token.
    
    Args:
        hours: Number of hours until expiry
    
    Returns:
        datetime: Expiry timestamp
    """
    return datetime.utcnow() + timedelta(hours=hours)


def extract_device_info(user_agent: str) -> dict:
    """
    Extract readable device information from user agent.
    
    Args:
        user_agent: HTTP User-Agent header
    
    Returns:
        dict: Device information (browser, os, device_type)
    """
    if not user_agent:
        return {"browser": "Unknown", "os": "Unknown", "device_type": "Unknown"}
    
    ua_lower = user_agent.lower()
    
    # Browser detection
    if "chrome" in ua_lower and "edg" not in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edg" in ua_lower:
        browser = "Edge"
    elif "opera" in ua_lower or "opr" in ua_lower:
        browser = "Opera"
    else:
        browser = "Other"
    
    # OS detection
    if "windows" in ua_lower:
        os = "Windows"
    elif "mac" in ua_lower or "darwin" in ua_lower:
        os = "macOS"
    elif "linux" in ua_lower:
        os = "Linux"
    elif "android" in ua_lower:
        os = "Android"
    elif "ios" in ua_lower or "iphone" in ua_lower or "ipad" in ua_lower:
        os = "iOS"
    else:
        os = "Other"
    
    # Device type detection
    if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
        device_type = "Mobile"
    elif "tablet" in ua_lower or "ipad" in ua_lower:
        device_type = "Tablet"
    else:
        device_type = "Desktop"
    
    return {
        "browser": browser,
        "os": os,
        "device_type": device_type
    }
