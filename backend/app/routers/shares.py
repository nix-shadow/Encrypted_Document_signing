"""
Share Routes Module - C3 in Architecture
Endpoints: /share, /revoke
Handles document sharing and access revocation
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas, services
from ..db import get_db
from ..deps import get_current_user
from ..utils.csrf import verify_csrf_token

router = APIRouter(prefix="/shares", tags=["shares"])


@router.post("/share", response_model=schemas.MessageResponse)
def share_document(
    payload: schemas.ShareDocumentRequest,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    """
    Share a document with another user by email.
    
    Process:
    1. Verify owner owns document
    2. Find recipient by email
    3. Decrypt AES key with owner's private key
    4. Re-encrypt AES key with recipient's public key
    5. Store share record in database
    6. Log audit event
    
    Security: Only document owner can share
    """
    user, private_key_pem = current
    
    # Get document and verify ownership
    doc = db.query(models.Document).filter_by(id=payload.document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Document not found"
        )
    
    if doc.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Only document owner can share"
        )
    
    # Find recipient by email
    recipient = db.query(models.User).filter_by(email=payload.recipient_email).first()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"User with email {payload.recipient_email} not found"
        )
    
    if recipient.id == user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Cannot share document with yourself"
        )
    
    # Check if already shared
    existing = services.document_service.get_share(db, doc.id, recipient.id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Document already shared with this user"
        )
    
    # Share document (decrypt key with owner's private key, re-encrypt with recipient's public key)
    services.share_document(db, doc, private_key_pem, recipient)
    
    # Log audit event
    services.audit_service.log_share_granted(db, user.id, doc.id, recipient.id)
    
    return {"message": f"Document successfully shared with {recipient.email}"}


@router.post("/revoke", response_model=schemas.MessageResponse)
def revoke_share(
    payload: schemas.ShareDocumentRequest,
    current=Depends(get_current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(verify_csrf_token)
):
    """
    Revoke document access from a user.
    
    Process:
    1. Verify owner owns document
    2. Find recipient by email
    3. Remove share record from database
    4. Log audit event
    
    Security: Only document owner can revoke
    """
    user, _ = current
    
    # Get document and verify ownership
    doc = db.query(models.Document).filter_by(id=payload.document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Document not found"
        )
    
    if doc.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Only document owner can revoke access"
        )
    
    # Find recipient by email
    recipient = db.query(models.User).filter_by(email=payload.recipient_email).first()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"User with email {payload.recipient_email} not found"
        )
    
    # Revoke share
    services.revoke_share(db, doc, recipient, user.id)
    
    # Log audit event
    services.audit_service.log_share_revoked(db, user.id, doc.id, recipient.id)
    
    return {"message": f"Document access revoked from {recipient.email}"}


@router.get("/shared-with-me", response_model=list[schemas.DocumentMeta])
def get_shared_documents(
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all documents shared with the current user.
    
    Returns: List of document metadata for documents shared with user
    """
    user, _ = current
    
    # Query shares where user is the recipient
    shares = db.query(models.DocumentShare).filter_by(recipient_id=user.id).all()
    
    # Get document details for each share
    documents = []
    for share in shares:
        doc = db.query(models.Document).filter_by(id=share.document_id).first()
        if doc:
            documents.append(doc)
    
    return documents


@router.get("/shared-by-me", response_model=list[schemas.ShareInfo])
def get_my_shares(
    current=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all documents the current user has shared with others.
    
    Returns: List of share records with recipient info
    """
    user, _ = current
    
    # Query documents owned by user
    docs = db.query(models.Document).filter_by(owner_id=user.id).all()
    doc_ids = [doc.id for doc in docs]
    
    # Query shares for these documents
    shares = db.query(models.DocumentShare).filter(
        models.DocumentShare.document_id.in_(doc_ids)
    ).all()
    
    # Build response with recipient and document info
    result = []
    for share in shares:
        recipient = db.query(models.User).filter_by(id=share.recipient_id).first()
        doc = db.query(models.Document).filter_by(id=share.document_id).first()
        
        if recipient and doc:
            result.append({
                "share_id": share.id,
                "document_id": doc.id,
                "document_name": doc.filename,
                "recipient_email": recipient.email,
                "recipient_name": recipient.username,
                "shared_at": share.created_at
            })
    
    return result
