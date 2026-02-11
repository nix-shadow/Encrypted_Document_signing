from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from .. import crypto, schemas, security, services
from ..config import get_settings
from ..db import get_db
from ..deps import get_current_user, get_admin_user
from ..models import UserRole, ApprovalStatus, PendingLogin, User
from ..utils import validators
from ..utils.csrf import generate_csrf_token, verify_csrf_token
from ..utils.rate_limiter import rate_limit
from ..services import mfa_service, device_service

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


@router.get("/csrf-token")
def get_csrf_token():
    """Generate and return a CSRF token for the client."""
    token = generate_csrf_token()
    return {"csrf_token": token}


@router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: schemas.UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Public registration endpoint for new users.
    Creates a new user account with RSA key pair generation.
    Requires admin approval before the user can log in.
    """
    # Validate input
    if not validators.validate_email(payload.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")
    valid, msg = validators.validate_password(payload.password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # Check if user already exists
    existing = services.get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    # Create user (will require admin approval)
    user = services.create_user(db, payload.email, payload.password)
    
    # Register device if fingerprint provided
    if payload.device_fingerprint:
        device_service.register_device(db, user.id, payload.device_fingerprint, request)
    
    return user


@router.post("/admin/create-user", response_model=schemas.AdminUserResponse, status_code=status.HTTP_201_CREATED)
def admin_create_user(
    payload: schemas.AdminCreateUserRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user),
    _csrf: None = Depends(verify_csrf_token)
):
    """Admin-only endpoint to create new users."""
    admin, _ = admin_user
    
    # Validate input
    if not validators.validate_email(payload.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")
    valid, msg = validators.validate_password(payload.password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    
    # Check if user already exists
    existing = services.get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    # Determine role
    role = 'admin' if payload.role.lower() == "admin" else 'user'
    
    # Create user
    user = services.create_user(db, payload.email, payload.password, role=role)
    
    # Auto-approve the user (admin created)
    user.is_approved = True
    user.approved_by = admin.id
    user.approved_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    # Log action
    services.create_audit_log(
        db, admin.id, "admin.user_created", "user", user.id, 
        f"Admin created user: {user.email} with role: {role}"
    )
    
    return user


@router.post("/login", response_model=schemas.MessageResponse)
@rate_limit(max_calls=5, period_seconds=900)
def login(
    payload: schemas.LoginWithDeviceRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    """
    Login with admin approval workflow.
    
    Flow:
    1. Verify credentials
    2. Check if user is approved
    3. Check device trust
    4. Create pending login for approval
    5. If admin, bypass approval
    6. If MFA enabled, require token
    """
    if security.session_manager.too_many_attempts(payload.email):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts. Try later")
    
    user = services.get_user_by_email(db, payload.email)
    if not user or not security.verify_password(payload.password, user.password_hash):
        security.session_manager.record_login_attempt(payload.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # Check if user is approved by admin
    if user.role != 'admin' and not user.is_approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Your account is pending admin approval. Please contact administrator."
        )
    
    # Get device info
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
    
    # Get or create device
    device, is_new = device_service.get_or_create_device(db, user.id, user_agent, ip_address)
    
    # Check device approval (admin bypass)
    if user.role != 'admin' and not device.is_trusted:
        # Create pending device auth
        pending = device_service.create_pending_auth(db, user.id, device.device_fingerprint)
        
        services.create_audit_log(
            db, user.id, "auth.device_unauthorized", "device", device.id,
            f"Unauthorized device login attempt from {device.device_name}"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "device_not_verified",
                "message": "This device is not authorized. Please contact admin for approval.",
                "auth_token": pending.auth_token,  # For admin to approve
                "device_name": device.device_name
            }
        )
    
    # Create pending login for non-admin users
    if user.role != 'admin':
        # Check if there's an approved pending login for this device
        approved_login = db.query(PendingLogin).filter(
            PendingLogin.user_id == user.id,
            PendingLogin.device_fingerprint == device.device_fingerprint,
            PendingLogin.status == 'approved',
            PendingLogin.expires_at > datetime.utcnow()
        ).first()
        
        if approved_login:
            # Delete the approved login record (one-time use)
            db.delete(approved_login)
            db.commit()
            
            services.create_audit_log(
                db, user.id, "auth.login_approved_used", "user", user.id,
                f"Used approved login from {device.device_name}"
            )
            
            # Proceed with login below (don't return here)
        else:
            # Check if there's already a pending login
            existing_pending = db.query(PendingLogin).filter(
                PendingLogin.user_id == user.id,
                PendingLogin.status == 'pending',
                PendingLogin.expires_at > datetime.utcnow()
            ).first()
            
            if not existing_pending:
                # Create new pending login
                pending_login = PendingLogin(
                    user_id=user.id,
                    device_fingerprint=device.device_fingerprint,
                    device_name=device.device_name,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    status='pending',
                    expires_at=datetime.utcnow() + timedelta(minutes=15)
                )
                db.add(pending_login)
                db.commit()
                
                services.create_audit_log(
                    db, user.id, "auth.login_pending", "user", user.id,
                    f"Login attempt pending approval from {device.device_name}"
                )
            
            raise HTTPException(
                status_code=status.HTTP_202_ACCEPTED,
                detail={
                    "error": "login_pending_approval",
                    "message": "Login request submitted. Waiting for admin approval.",
                    "poll_endpoint": "/api/auth/login/status"
                }
            )
    
    # Admin bypass OR approved login - proceed with actual login
    # Check MFA if enabled
    mfa_enabled = mfa_service.is_mfa_enabled(db, user.id)
    if mfa_enabled:
        if not payload.mfa_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "mfa_required", "message": "MFA token required"}
            )
        
        if not mfa_service.verify_mfa_token(db, user.id, payload.mfa_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")
    
    # Decrypt private key
    private_key_pem = crypto.decrypt_private_key(user.private_key_encrypted, payload.password)
    
    # Create session
    token = security.session_manager.create_session(user.id, private_key_pem)
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        secure=False,
        samesite="lax",
    )
    
    login_type = "Admin" if user.role == 'admin' else "User"
    services.create_audit_log(db, user.id, "auth.login", "user", user.id, f"{login_type} login from {device.device_name}")
    
    return {"message": "Login successful"}


@router.post("/logout", response_model=schemas.MessageResponse)
def logout(response: Response, session_token: str | None = Cookie(default=None)):
    if session_token:
        security.session_manager.destroy_session(session_token)
    response.delete_cookie("session_token")
    return {"message": "Logged out"}


@router.get("/login/status", response_model=schemas.LoginPollResponse)
def check_login_status(
    email: str,
    db: Session = Depends(get_db)
):
    """Poll endpoint for users to check if their login has been approved."""
    user = services.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Find most recent pending login
    pending = db.query(PendingLogin).filter(
        PendingLogin.user_id == user.id,
        PendingLogin.expires_at > datetime.utcnow()
    ).order_by(PendingLogin.created_at.desc()).first()
    
    if not pending:
        return {
            "status": "expired",
            "message": "No pending login found. Please try logging in again.",
            "session_token": None
        }
    
    if pending.status == 'approved':
        # Generate session token
        # Note: User needs to provide password again to decrypt private key
        return {
            "status": "approved",
            "message": "Login approved! Please complete login with your password.",
            "session_token": None
        }
    elif pending.status == 'rejected':
        return {
            "status": "rejected",
            "message": "Login request was rejected by administrator.",
            "session_token": None
        }
    else:
        return {
            "status": "pending",
            "message": "Login request is pending admin approval.",
            "session_token": None
        }


@router.post("/admin/approve-login/{pending_id}", response_model=schemas.MessageResponse)
def admin_approve_login(
    pending_id: int,
    payload: schemas.ApprovalRequest,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user),
    _csrf: None = Depends(verify_csrf_token)
):
    """Admin endpoint to approve or reject pending login requests."""
    admin, _ = admin_user
    
    pending = db.query(PendingLogin).filter(PendingLogin.id == pending_id).first()
    if not pending:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending login not found")
    
    if pending.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login request expired")
    
    if pending.status != 'pending':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login already processed")
    
    # Update status
    pending.status = 'approved' if payload.approve else 'rejected'
    pending.approved_by = admin.id
    pending.approved_at = datetime.utcnow()
    db.commit()
    
    # Log action
    action = "approved" if payload.approve else "rejected"
    services.create_audit_log(
        db, admin.id, f"admin.login_{action}", "login", pending_id,
        f"Admin {action} login for user ID {pending.user_id}"
    )
    
    return {"message": f"Login request {action} successfully"}


@router.post("/admin/approve-device/{pending_id}", response_model=schemas.MessageResponse)
def admin_approve_device(
    pending_id: int,
    payload: schemas.ApprovalRequest,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user),
    _csrf: None = Depends(verify_csrf_token)
):
    """Admin endpoint to approve or reject pending device authorization."""
    admin, _ = admin_user
    
    from ..models import PendingDeviceAuth
    pending = db.query(PendingDeviceAuth).filter(PendingDeviceAuth.id == pending_id).first()
    if not pending:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending device not found")
    
    if pending.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device authorization expired")
    
    if pending.status != 'pending':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device already processed")
    
    # Update status
    pending.status = 'approved' if payload.approve else 'rejected'
    pending.approved_by = admin.id
    db.commit()
    
    # If approved, trust the device
    if payload.approve:
        device_service.create_trusted_device(
            db, pending.user_id, pending.device_fingerprint, 
            pending.device_name, is_trusted=True
        )
    
    # Log action
    action = "approved" if payload.approve else "rejected"
    services.create_audit_log(
        db, admin.id, f"admin.device_{action}", "device", pending_id,
        f"Admin {action} device for user ID {pending.user_id}"
    )
    
    return {"message": f"Device {action} successfully"}


@router.get("/admin/pending-logins", response_model=list[schemas.PendingLoginResponse])
def list_pending_logins(
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Admin endpoint to list all pending login requests."""
    pending_logins = db.query(PendingLogin).filter(
        PendingLogin.status == 'pending',
        PendingLogin.expires_at > datetime.utcnow()
    ).order_by(PendingLogin.created_at.desc()).all()
    
    result = []
    for pl in pending_logins:
        user = db.query(User).filter(User.id == pl.user_id).first()
        result.append({
            "id": pl.id,
            "user_id": pl.user_id,
            "user_email": user.email if user else "Unknown",
            "device_name": pl.device_name,
            "ip_address": pl.ip_address,
            "status": pl.status,
            "created_at": pl.created_at
        })
    
    return result


@router.get("/admin/pending-devices", response_model=list[schemas.PendingDeviceResponse])
def list_pending_devices(
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Admin endpoint to list all pending device authorizations."""
    from ..models import PendingDeviceAuth
    
    pending_devices = db.query(PendingDeviceAuth).filter(
        PendingDeviceAuth.status == 'pending',
        PendingDeviceAuth.expires_at > datetime.utcnow()
    ).order_by(PendingDeviceAuth.created_at.desc()).all()
    
    result = []
    for pd in pending_devices:
        user = db.query(User).filter(User.id == pd.user_id).first()
        result.append({
            "id": pd.id,
            "user_id": pd.user_id,
            "user_email": user.email if user else "Unknown",
            "device_name": pd.device_name if pd.device_name and pd.device_name.strip() else "Unknown Device",
            "device_fingerprint": pd.device_fingerprint if pd.device_fingerprint and pd.device_fingerprint.strip() else "N/A",
            "ip_address": pd.ip_address if pd.ip_address and pd.ip_address.strip() else "Unknown",
            "status": pd.status,
            "created_at": pd.created_at
        })
    
    return result



# MFA Endpoints
@router.post("/mfa/enroll", response_model=schemas.MFAEnrollResponse)
def enroll_mfa(
    db: Session = Depends(get_db),
    current_user: int = Depends(get_current_user)
):
    """Start MFA enrollment - returns secret, QR code, and backup codes."""
    try:
        secret, qr_code, backup_codes = mfa_service.create_mfa_secret(db, current_user)
        return {
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/mfa/enable", response_model=schemas.MessageResponse)
def enable_mfa(
    payload: schemas.MFAVerifyRequest,
    db: Session = Depends(get_db),
    current_user: int = Depends(get_current_user)
):
    """Verify TOTP token and enable MFA."""
    if mfa_service.enable_mfa(db, current_user, payload.token):
        services.create_audit_log(db, current_user, "mfa.enabled", "user", current_user, "MFA enabled")
        return {"message": "MFA enabled successfully"}
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token")


@router.post("/mfa/disable", response_model=schemas.MessageResponse)
def disable_mfa(
    db: Session = Depends(get_db),
    current_user: int = Depends(get_current_user)
):
    """Disable MFA for current user."""
    if mfa_service.disable_mfa(db, current_user):
        services.create_audit_log(db, current_user, "mfa.disabled", "user", current_user, "MFA disabled")
        return {"message": "MFA disabled successfully"}
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA not enabled")


@router.get("/mfa/status", response_model=schemas.MFAStatusResponse)
def get_mfa_status(
    db: Session = Depends(get_db),
    current_user: int = Depends(get_current_user)
):
    """Get MFA status for current user."""
    enabled = mfa_service.is_mfa_enabled(db, current_user)
    backup_codes = mfa_service.get_backup_codes(db, current_user)
    
    return {
        "enabled": enabled,
        "backup_codes_remaining": len(backup_codes) if backup_codes else None
    }


# Device Management Endpoints
@router.get("/devices", response_model=schemas.DeviceListResponse)
def list_devices(
    db: Session = Depends(get_db),
    current_user: int = Depends(get_current_user)
):
    """List all devices for current user."""
    devices = device_service.get_user_devices(db, current_user)
    return {"devices": devices}


@router.post("/devices/{device_id}/revoke", response_model=schemas.MessageResponse)
def revoke_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: int = Depends(get_current_user)
):
    """Revoke trust for a device."""
    if device_service.revoke_device(db, device_id, current_user):
        services.create_audit_log(db, current_user, "device.revoked", "device", device_id, "Device trust revoked")
        return {"message": "Device revoked successfully"}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")


@router.post("/devices/authorize", response_model=schemas.MessageResponse)
def authorize_device(
    payload: schemas.DeviceAuthRequest,
    db: Session = Depends(get_db)
):
    """Authorize a new device using the token from email/SMS."""
    pending = device_service.verify_pending_auth(db, payload.auth_token)
    
    if not pending:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired authorization token")
    
    services.create_audit_log(
        db, 
        pending.user_id, 
        "device.authorized", 
        "device", 
        None, 
        f"New device authorized: {pending.device_fingerprint[:16]}..."
    )
    
    return {"message": "Device authorized successfully. You can now log in from this device."}


# Admin User Management Endpoints
@router.get("/admin/users", response_model=list[schemas.AdminUserResponse])
def list_all_users(
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """List all users in the system (admin only)."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return users


@router.get("/admin/pending-users", response_model=list[schemas.AdminUserResponse])
def list_pending_users(
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """List all users pending approval (admin only)."""
    users = db.query(User).filter(User.is_approved == False).order_by(User.created_at.desc()).all()
    return users


@router.post("/admin/approve-user/{user_id}", response_model=schemas.MessageResponse)
def approve_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Approve a user account (admin only)."""
    admin, _ = admin_user
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.is_approved:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already approved")
    
    user.is_approved = True
    user.approved_by = admin.id
    user.approved_at = datetime.utcnow()
    db.commit()
    
    services.create_audit_log(
        db, admin.id, "admin.user_approved", "user", user.id,
        f"Admin approved user: {user.email}"
    )
    
    return {"message": f"User {user.email} approved successfully"}


@router.post("/admin/reject-user/{user_id}", response_model=schemas.MessageResponse)
def reject_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Reject and delete a user account (admin only)."""
    admin, _ = admin_user
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.role == 'admin':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot reject admin users")
    
    email = user.email
    
    services.create_audit_log(
        db, admin.id, "admin.user_rejected", "user", user.id,
        f"Admin rejected user: {email}"
    )
    
    db.delete(user)
    db.commit()
    
    return {"message": f"User {email} rejected and deleted"}


@router.delete("/admin/delete-user/{user_id}", response_model=schemas.MessageResponse)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Delete a user account (admin only)."""
    admin, _ = admin_user
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.role == 'admin':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete admin users")
    
    if user.id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete yourself")
    
    email = user.email
    
    services.create_audit_log(
        db, admin.id, "admin.user_deleted", "user", user.id,
        f"Admin deleted user: {email}"
    )
    
    db.delete(user)
    db.commit()
    
    return {"message": f"User {email} deleted successfully"}


@router.get("/admin/all-devices")
def list_all_devices(
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Admin endpoint to list all trusted devices across all users."""
    from ..models import TrustedDevice
    
    devices = db.query(TrustedDevice).order_by(TrustedDevice.last_used_at.desc()).all()
    
    result = []
    for device in devices:
        user = db.query(User).filter(User.id == device.user_id).first()
        result.append({
            "id": device.id,
            "user_id": device.user_id,
            "user_email": user.email if user else "Unknown",
            "device_name": device.device_name if device.device_name and device.device_name.strip() else "Unknown Device",
            "device_fingerprint": device.device_fingerprint if device.device_fingerprint and device.device_fingerprint.strip() else "N/A",
            "ip_address": device.ip_address if device.ip_address and device.ip_address.strip() else "Unknown",
            "is_trusted": device.is_trusted,
            "is_active": device.is_active,
            "last_used_at": device.last_used_at,
            "created_at": device.created_at
        })
    
    return result


@router.post("/admin/trust-device/{device_id}", response_model=schemas.MessageResponse)
def admin_trust_device(
    device_id: int,
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user),
    _csrf: None = Depends(verify_csrf_token)
):
    """Admin endpoint to directly trust a device from trusted_devices table."""
    admin, _ = admin_user
    
    from ..models import TrustedDevice
    device = db.query(TrustedDevice).filter(TrustedDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    
    # Set device as trusted
    device.is_trusted = True
    db.commit()
    
    # Log action
    services.create_audit_log(
        db, admin.id, "admin.device_trusted", "device", device_id,
        f"Admin trusted device for user ID {device.user_id}"
    )
    
    return {"message": "Device trusted successfully"}


@router.get("/admin/all-documents")
def list_all_documents(
    db: Session = Depends(get_db),
    admin_user: tuple = Depends(get_admin_user)
):
    """Admin endpoint to list ALL documents in the system."""
    from ..models import Document
    
    documents = db.query(Document).order_by(Document.created_at.desc()).all()
    
    result = []
    for doc in documents:
        owner = db.query(User).filter(User.id == doc.owner_id).first()
        result.append({
            "id": doc.id,
            "filename": doc.filename,
            "content_type": doc.content_type,
            "owner_id": doc.owner_id,
            "owner_email": owner.email if owner else "Unknown",
            "has_pdf_password": doc.has_pdf_password,
            "created_at": doc.created_at
        })
    
    return result
