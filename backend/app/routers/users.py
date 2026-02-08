from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import schemas, services
from ..db import get_db
from ..deps import get_current_user
from ..schemas_extra import PasswordChangeRequest
from ..utils import validators
from ..services import mfa_service, audit_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=schemas.UserOut)
def read_me(current=Depends(get_current_user), db: Session = Depends(get_db)):
    user, _ = current
    return user


@router.post("/change-password", response_model=schemas.MessageResponse)
def change_password(
    payload: PasswordChangeRequest,
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, _ = current
    valid, msg = validators.validate_password(payload.new_password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    success = services.change_password(db, user, payload.old_password, payload.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Old password incorrect")
    
    return {"message": "Password changed"}


@router.get("/audit-logs")
def get_audit_logs(
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50
):
    """Get user's audit log entries."""
    user, _ = current
    logs = audit_service.get_user_audit_logs(db, user.id, limit)
    return logs


@router.post("/mfa/setup")
def setup_mfa(
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initialize MFA setup for user."""
    user, _ = current
    secret, qr_code_base64, backup_codes = mfa_service.create_mfa_secret(db, user.id)
    return {
        "secret": secret,
        "qr_code": qr_code_base64,
        "backup_codes": backup_codes
    }


@router.post("/mfa/enable", response_model=schemas.MessageResponse)
def enable_mfa(
    payload: dict,
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enable MFA after verifying token."""
    user, _ = current
    token = payload.get("token")
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token required")
    
    success = mfa_service.enable_mfa(db, user.id, token)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    
    audit_service.create_audit_log(db, user.id, "mfa.enabled", "user", user.id, "MFA enabled")
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable", response_model=schemas.MessageResponse)
def disable_mfa(
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable MFA for user."""
    user, _ = current
    success = mfa_service.disable_mfa(db, user.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MFA not enabled")
    
    audit_service.create_audit_log(db, user.id, "mfa.disabled", "user", user.id, "MFA disabled")
    return {"message": "MFA disabled"}


@router.get("/mfa/status")
def get_mfa_status(
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Check if MFA is enabled for user."""
    user, _ = current
    enabled = mfa_service.is_mfa_enabled(db, user.id)
    return {"enabled": enabled}


@router.get("/trusted-devices")
def get_trusted_devices(
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's trusted devices."""
    user, _ = current
    from ..models import TrustedDevice
    devices = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id,
        TrustedDevice.is_active == True
    ).order_by(TrustedDevice.last_used_at.desc()).all()
    
    return [{
        "id": d.id,
        "device_name": d.device_name or "Unknown Device",
        "device_fingerprint": d.device_fingerprint,
        "ip_address": d.ip_address or "Unknown",
        "is_trusted": d.is_trusted,
        "last_used_at": d.last_used_at,
        "created_at": d.created_at
    } for d in devices]
