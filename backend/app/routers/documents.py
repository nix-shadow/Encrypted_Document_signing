import base64
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime

from .. import crypto, models, schemas, services
from ..db import get_db
from ..deps import get_current_user, get_admin_user
from ..models import ViewingSession, UserRole, ApprovalStatus
from ..utils import validators
from ..utils.csrf import verify_csrf_token
from ..services import device_service

router = APIRouter(prefix="/documents", tags=["documents"])


def _require_owner(document: models.Document, user_id: int):
    if document.owner_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not the owner")


@router.post("/upload", response_model=schemas.DocumentMeta)
async def upload_document(
    file: UploadFile = File(...),
    pdf_password: Optional[str] = Form(None),
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    user, private_key_pem = current
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")
    if len(raw) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File too large (max 50MB)")
    
    filename = validators.sanitize_filename(file.filename)
    valid, msg = validators.validate_file_type(filename, file.content_type or "")
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    doc = services.create_document(
        db=db,
        owner=user,
        filename=filename,
        content_type=file.content_type or "application/octet-stream",
        plaintext=raw,
        private_key_pem=private_key_pem,
        pdf_password=pdf_password,
    )
    return doc


@router.get("", response_model=list[schemas.DocumentMeta])
def list_documents(current=Depends(get_current_user), db: Session = Depends(get_db)):
    user, _ = current
    docs = services.list_documents_for_user(db, user)
    return docs


@router.get("/{document_id}", response_model=schemas.DocumentResponse)
def fetch_document(
    document_id: int,
    request: Request,
    pdf_password: Optional[str] = None,
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, private_key_pem = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Check if user needs viewing approval (non-admin, non-owner)
    if user.role != 'admin' and doc.owner_id != user.id:
        # Get device info
        user_agent = request.headers.get("user-agent", "unknown")
        client_host = request.client.host if request.client else "127.0.0.1"
        ip_address = request.headers.get("x-forwarded-for", client_host).split(",")[0].strip()
        device, _ = device_service.get_or_create_device(db, user.id, user_agent, ip_address)
        
        # Check for existing viewing session
        existing_session = db.query(ViewingSession).filter(
            ViewingSession.document_id == document_id,
            ViewingSession.user_id == user.id,
            ViewingSession.device_fingerprint == device.device_fingerprint,
            ViewingSession.status == 'approved',
            ViewingSession.ended_at.is_(None)
        ).first()
        
        if not existing_session:
            # Create pending viewing session
            pending = db.query(ViewingSession).filter(
                ViewingSession.document_id == document_id,
                ViewingSession.user_id == user.id,
                ViewingSession.device_fingerprint == device.device_fingerprint,
                ViewingSession.status == 'pending'
            ).first()
            
            if not pending:
                viewing_session = ViewingSession(
                    document_id=document_id,
                    user_id=user.id,
                    device_fingerprint=device.device_fingerprint,
                    device_name=device.device_name,
                    ip_address=ip_address,
                    status='pending'
                )
                db.add(viewing_session)
                db.commit()
                
                services.create_audit_log(
                    db, user.id, "document.view_request", "document", document_id,
                    f"Requested viewing approval for document {doc.filename}"
                )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "viewing_approval_required",
                    "message": "Document viewing requires approval from owner or admin."
                }
            )
        
        # Update last active time
        existing_session.last_active_at = datetime.utcnow()
        db.commit()

    try:
        plaintext, verified, tampered, error_msg = services.decrypt_and_prepare_download(
            doc, user, private_key_pem, db, pdf_password
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    return schemas.DocumentResponse(
        id=doc.id,
        filename=doc.filename,
        content_type=doc.content_type,
        created_at=doc.created_at,
        owner_id=doc.owner_id,
        verified=verified,
        tampered=tampered,
        content_b64=base64.b64encode(plaintext).decode(),
    )


@router.post("/{document_id}/share", response_model=schemas.MessageResponse)
def share_document(
    document_id: int,
    payload: schemas.ShareRequest,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    user, private_key = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    _require_owner(doc, user.id)

    recipient = services.get_user_by_email(db, payload.recipient_email)
    if not recipient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found")
    
    existing = services.document_service.get_share(db, doc.id, recipient.id)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already shared")
    
    services.share_document(db, doc, private_key, recipient)
    return {"message": "Shared"}


@router.post("/{document_id}/revoke", response_model=schemas.MessageResponse)
def revoke_document(
    document_id: int,
    payload: schemas.ShareRequest,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    user, _ = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    _require_owner(doc, user.id)
    recipient = services.get_user_by_email(db, payload.recipient_email)
    if not recipient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found")
    services.revoke_share(db, doc, recipient, user.id)
    return {"message": "Revoked"}


@router.delete("/{document_id}", response_model=schemas.MessageResponse)
def delete_document(
    document_id: int,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    user, _ = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    _require_owner(doc, user.id)
    services.delete_document(db, doc, user.id)
    return {"message": "Deleted"}


@router.get("/{document_id}/viewing-sessions", response_model=list[schemas.ViewingSessionResponse])
def get_viewing_sessions(
    document_id: int,
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all active and pending viewing sessions for a document (owner/admin only)."""
    user, _ = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    
    # Only owner and admin can view sessions
    if user.role != 'admin' and doc.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    sessions = db.query(ViewingSession).filter(
        ViewingSession.document_id == document_id,
        ViewingSession.ended_at.is_(None)
    ).order_by(ViewingSession.started_at.desc()).all()
    
    result = []
    for session in sessions:
        viewer = db.query(models.User).filter(models.User.id == session.user_id).first()
        result.append({
            "id": session.id,
            "user_id": session.user_id,
            "user_email": viewer.email if viewer else "Unknown",
            "device_name": session.device_name,
            "ip_address": session.ip_address,
            "status": session.status,
            "started_at": session.started_at,
            "last_active_at": session.last_active_at
        })
    
    return result


@router.post("/{document_id}/approve-viewer/{session_id}", response_model=schemas.MessageResponse)
def approve_document_viewer(
    document_id: int,
    session_id: int,
    payload: schemas.ApprovalRequest,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    """Approve or reject a viewing request (owner/admin only)."""
    user, _ = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    
    # Only owner and admin can approve
    if user.role != 'admin' and doc.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    session = db.query(ViewingSession).filter(ViewingSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Viewing session not found")
    
    if session.status != 'pending':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session already processed")
    
    # Update status
    session.status = 'approved' if payload.approve else 'rejected'
    session.approved_by = user.id
    if payload.approve:
        session.last_active_at = datetime.utcnow()
    else:
        session.ended_at = datetime.utcnow()
    
    db.commit()
    
    # Log action
    action = "approved" if payload.approve else "rejected"
    services.create_audit_log(
        db, user.id, f"document.viewer_{action}", "document", document_id,
        f"{action.capitalize()} viewing request for user ID {session.user_id}"
    )
    
    return {"message": f"Viewing request {action} successfully"}


@router.post("/{document_id}/end-session/{session_id}", response_model=schemas.MessageResponse)
def end_viewing_session(
    document_id: int,
    session_id: int,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    """End an active viewing session (owner/admin only)."""
    user, _ = current
    doc = services.get_document(db, document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    
    # Only owner and admin can end sessions
    if user.role != 'admin' and doc.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    session = db.query(ViewingSession).filter(ViewingSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Viewing session not found")
    
    session.ended_at = datetime.utcnow()
    db.commit()
    
    services.create_audit_log(
        db, user.id, "document.session_ended", "document", document_id,
        f"Ended viewing session for user ID {session.user_id}"
    )
    
    return {"message": "Viewing session ended"}

