"""
Service layer for device fingerprinting and trust management.
"""
from sqlalchemy.orm import Session
from sqlalchemy import select, and_
from typing import Optional, List
from datetime import datetime

from app.models import TrustedDevice, PendingDeviceAuth
from app.utils import device as device_utils


def get_device_name(user_agent: str) -> str:
    """
    Extract human-readable device name from User-Agent.
    
    Args:
        user_agent: HTTP User-Agent header
    
    Returns:
        str: Device name like "Firefox on Linux"
    """
    info = device_utils.extract_device_info(user_agent)
    return f"{info['browser']} on {info['os']}"


def get_or_create_device(
    db: Session,
    user_id: int,
    user_agent: str,
    ip_address: str
) -> tuple[TrustedDevice, bool]:
    """
    Get existing trusted device or create new one.
    
    Args:
        db: Database session
        user_id: User ID
        user_agent: HTTP User-Agent header
        ip_address: Client IP address
    
    Returns:
        tuple[TrustedDevice, bool]: (device, is_new)
    """
    fingerprint = device_utils.generate_device_fingerprint(user_agent, ip_address)
    
    # Check if device exists
    existing = db.scalar(
        select(TrustedDevice).where(
            and_(
                TrustedDevice.user_id == user_id,
                TrustedDevice.device_fingerprint == fingerprint
            )
        )
    )
    
    if existing:
        # Update last used
        existing.last_used_at = datetime.utcnow()
        db.commit()
        return existing, False
    
    # Create new device (not trusted by default)
    device_info = device_utils.extract_device_info(user_agent)
    
    new_device = TrustedDevice(
        user_id=user_id,
        device_fingerprint=fingerprint,
        user_agent=user_agent,
        ip_address=ip_address,
        device_name=f"{device_info['browser']} on {device_info['os']}",
        is_trusted=False,  # Requires authorization
        is_active=True
    )
    
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    
    return new_device, True


def is_device_trusted(db: Session, user_id: int, user_agent: str, ip_address: str) -> bool:
    """
    Check if device is trusted for this user.
    
    Args:
        db: Database session
        user_id: User ID
        user_agent: HTTP User-Agent header
        ip_address: Client IP address
    
    Returns:
        bool: True if device is trusted
    """
    fingerprint = device_utils.generate_device_fingerprint(user_agent, ip_address)
    
    device = db.scalar(
        select(TrustedDevice).where(
            and_(
                TrustedDevice.user_id == user_id,
                TrustedDevice.device_fingerprint == fingerprint,
                TrustedDevice.is_trusted == True,
                TrustedDevice.is_active == True
            )
        )
    )
    
    return device is not None


def trust_device(db: Session, device_id: int) -> bool:
    """
    Mark a device as trusted.
    
    Args:
        db: Database session
        device_id: Device ID
    
    Returns:
        bool: True if successful
    """
    device = db.get(TrustedDevice, device_id)
    
    if not device:
        return False
    
    device.is_trusted = True
    device.last_used_at = datetime.utcnow()
    db.commit()
    
    return True


def revoke_device(db: Session, device_id: int, user_id: int) -> bool:
    """
    Revoke trust for a device.
    
    Args:
        db: Database session
        device_id: Device ID
        user_id: User ID (for authorization)
    
    Returns:
        bool: True if successful
    """
    device = db.scalar(
        select(TrustedDevice).where(
            and_(
                TrustedDevice.device_id == device_id,
                TrustedDevice.user_id == user_id
            )
        )
    )
    
    if not device:
        return False
    
    device.is_active = False
    device.is_trusted = False
    db.commit()
    
    return True


def get_user_devices(db: Session, user_id: int) -> List[TrustedDevice]:
    """
    Get all devices for a user.
    
    Args:
        db: Database session
        user_id: User ID
    
    Returns:
        List[TrustedDevice]: List of devices
    """
    return list(db.scalars(
        select(TrustedDevice)
        .where(TrustedDevice.user_id == user_id)
        .order_by(TrustedDevice.last_used_at.desc())
    ))


def create_pending_auth(
    db: Session,
    user_id: int,
    device_fingerprint: str
) -> PendingDeviceAuth:
    """
    Create a pending device authorization request.
    
    Args:
        db: Database session
        user_id: User ID
        device_fingerprint: Device fingerprint
    
    Returns:
        PendingDeviceAuth: Pending authorization record
    """
    # Generate token
    token = device_utils.generate_device_auth_token()
    expiry = device_utils.get_token_expiry(hours=24)
    
    # Delete any existing pending auth for this device
    db.query(PendingDeviceAuth).filter(
        and_(
            PendingDeviceAuth.user_id == user_id,
            PendingDeviceAuth.device_fingerprint == device_fingerprint
        )
    ).delete()
    
    # Create new pending auth
    pending = PendingDeviceAuth(
        user_id=user_id,
        device_fingerprint=device_fingerprint,
        auth_token=token,
        expires_at=expiry
    )
    
    db.add(pending)
    db.commit()
    db.refresh(pending)
    
    return pending


def verify_pending_auth(db: Session, token: str) -> Optional[PendingDeviceAuth]:
    """
    Verify a pending device authorization token.
    
    Args:
        db: Database session
        token: Authorization token
    
    Returns:
        PendingDeviceAuth or None: Pending auth record if valid
    """
    pending = db.scalar(
        select(PendingDeviceAuth).where(
            and_(
                PendingDeviceAuth.auth_token == token,
                PendingDeviceAuth.expires_at > datetime.utcnow()
            )
        )
    )
    
    if not pending:
        return None
    
    # Trust the device
    device = db.scalar(
        select(TrustedDevice).where(
            and_(
                TrustedDevice.user_id == pending.user_id,
                TrustedDevice.device_fingerprint == pending.device_fingerprint
            )
        )
    )
    
    if device:
        device.is_trusted = True
        device.last_used_at = datetime.utcnow()
    
    db.commit()
    
    return pending
