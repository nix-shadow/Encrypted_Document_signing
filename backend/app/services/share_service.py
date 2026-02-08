"""
Document sharing service module.

This module handles secure document sharing between users by re-encrypting
AES keys with recipient public keys, enabling access without sharing the
document owner's private key.
"""

from typing import Optional

from sqlalchemy.orm import Session

from .. import crypto
from ..models import Document, DocumentShare, User
from .audit_service import create_audit_log
from .document_service import get_share


def share_document(
    db: Session,
    document: Document,
    owner_private_key: str,
    recipient: User,
) -> DocumentShare:
    """
    Share a document with a recipient by re-encrypting the AES key.
    
    This function implements secure key sharing:
    1. Decrypt the document's AES key using owner's private key
    2. Re-encrypt the AES key using recipient's public key
    3. Store the re-encrypted key in a new DocumentShare record
    4. Create an audit log entry
    
    Args:
        db: Database session
        document: Document to share
        owner_private_key: Owner's RSA private key in PEM format
        recipient: User to share the document with
        
    Returns:
        Created DocumentShare object
        
    Security Notes:
        - AES key is never stored in plaintext
        - Recipient cannot access owner's private key
        - Each recipient gets their own encrypted copy of the AES key
        - Owner can revoke access by deleting the DocumentShare record
    """
    # Decrypt AES key with owner's private key
    aes_key = crypto.decrypt_aes_key_with_private_key(document.aes_key_encrypted_owner, owner_private_key)
    
    # Re-encrypt with recipient's public key
    encrypted_for_recipient = crypto.encrypt_aes_key_for_public_key(aes_key, recipient.public_key_pem)
    
    share = DocumentShare(
        document_id=document.id,
        recipient_id=recipient.id,
        encrypted_aes_key=encrypted_for_recipient,
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    create_audit_log(db, document.owner_id, "document.share", "document", document.id, f"Shared with {recipient.email}")
    return share


def revoke_share(db: Session, document: Document, recipient: User, owner_id: int) -> None:
    """
    Revoke a recipient's access to a document.
    
    Deletes the DocumentShare record, which removes the recipient's ability
    to decrypt the document's AES key.
    
    Args:
        db: Database session
        document: Document to revoke access to
        recipient: User whose access to revoke
        owner_id: ID of document owner (for audit log)
        
    Note:
        If the share doesn't exist, this function does nothing.
        Recipient can no longer access the document after revocation.
    """
    share = get_share(db, document.id, recipient.id)
    if share:
        db.delete(share)
        db.commit()
        create_audit_log(db, owner_id, "document.revoke", "document", document.id, f"Revoked {recipient.email}")


def list_shares(db: Session, document: Document) -> list[DocumentShare]:
    """
    List all users who have access to a document via sharing.
    
    Args:
        db: Database session
        document: Document to list shares for
        
    Returns:
        List of DocumentShare objects (includes recipient information)
    """
    return db.query(DocumentShare).filter(DocumentShare.document_id == document.id).all()
