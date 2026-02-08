"""
Service layer for multi-factor authentication operations.
"""
from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import Optional, Tuple
from datetime import datetime

from app.models import MFASecret, User
from app.utils import mfa


def create_mfa_secret(db: Session, user_id: int) -> Tuple[str, str, list]:
    """
    Create a new MFA secret for user enrollment.
    
    Args:
        db: Database session
        user_id: ID of user enrolling in MFA
    
    Returns:
        Tuple[str, str, list]: (secret, qr_code_data_url, backup_codes)
    """
    # Generate secret and backup codes
    secret = mfa.generate_mfa_secret()
    backup_codes = mfa.generate_backup_codes(count=10)
    
    # Get user for QR code
    user = db.get(User, user_id)
    if not user:
        raise ValueError("User not found")
    
    # Generate QR code
    qr_code = mfa.generate_qr_code(username=user.email, secret=secret)
    
    # Store in database (disabled by default until user verifies)
    mfa_record = db.scalar(select(MFASecret).where(MFASecret.user_id == user_id))
    
    if mfa_record:
        # Update existing
        mfa_record.secret = secret
        mfa_record.backup_codes = backup_codes
        mfa_record.is_enabled = False  # Require verification
        mfa_record.created_at = datetime.utcnow()
    else:
        # Create new
        mfa_record = MFASecret(
            user_id=user_id,
            secret=secret,
            backup_codes=backup_codes,
            is_enabled=False
        )
        db.add(mfa_record)
    
    db.commit()
    
    return secret, qr_code, backup_codes


def enable_mfa(db: Session, user_id: int, verification_token: str) -> bool:
    """
    Enable MFA after user verifies with a token.
    
    Args:
        db: Database session
        user_id: User ID
        verification_token: TOTP token to verify setup
    
    Returns:
        bool: True if enabled successfully
    """
    mfa_record = db.scalar(select(MFASecret).where(MFASecret.user_id == user_id))
    
    if not mfa_record:
        return False
    
    # Verify token
    if not mfa.verify_totp_token(mfa_record.secret, verification_token):
        return False
    
    # Enable MFA
    mfa_record.is_enabled = True
    db.commit()
    
    return True


def disable_mfa(db: Session, user_id: int) -> bool:
    """
    Disable MFA for a user.
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        bool: True if disabled successfully
    """
    mfa_record = db.scalar(select(MFASecret).where(MFASecret.user_id == user_id))
    
    if not mfa_record:
        return False
    
    mfa_record.is_enabled = False
    db.commit()
    
    return True


def verify_mfa_token(db: Session, user_id: int, token: str) -> bool:
    """
    Verify a TOTP token or backup code.
    
    Args:
        db: Database session
        user_id: User ID
        token: TOTP token or backup code
    
    Returns:
        bool: True if valid
    """
    mfa_record = db.scalar(select(MFASecret).where(MFASecret.user_id == user_id))
    
    if not mfa_record or not mfa_record.is_enabled:
        return False
    
    # Try TOTP first
    if mfa.verify_totp_token(mfa_record.secret, token):
        return True
    
    # Try backup code
    is_valid, remaining_codes = mfa.verify_backup_code(mfa_record.backup_codes or [], token)
    
    if is_valid:
        # Update backup codes (remove used code)
        mfa_record.backup_codes = remaining_codes
        db.commit()
        return True
    
    return False


def is_mfa_enabled(db: Session, user_id: int) -> bool:
    """
    Check if MFA is enabled for user.
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        bool: True if MFA is enabled
    """
    mfa_record = db.scalar(select(MFASecret).where(MFASecret.user_id == user_id))
    return mfa_record is not None and mfa_record.is_enabled


def get_backup_codes(db: Session, user_id: int) -> Optional[list]:
    """
    Get remaining backup codes for user.
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        list or None: Backup codes if available
    """
    mfa_record = db.scalar(select(MFASecret).where(MFASecret.user_id == user_id))
    
    if not mfa_record:
        return None
    
    return mfa_record.backup_codes
