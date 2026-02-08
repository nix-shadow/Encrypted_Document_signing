"""
Document service module for managing encrypted documents.

This module provides functions for document creation, encryption, decryption,
verification, and sharing. It implements AES-256-GCM encryption with RSA-based
key management and digital signatures for authenticity.
"""

from typing import Iterable, Optional
from sqlalchemy.orm import Session

from .. import crypto
from ..models import Document, DocumentShare, User
from ..utils import pdf_protection
from .audit_service import create_audit_log


def create_document(
    db: Session,
    owner: User,
    filename: str,
    content_type: str,
    plaintext: bytes,
    private_key_pem: str,
    pdf_password: Optional[str] = None,
) -> Document:
    """
    Create an encrypted document with digital signature.
    
    This function performs the following operations:
    1. Generate a random 256-bit AES key
    2. Encrypt the document content using AES-256-GCM
    3. Compute SHA-256 hash of the plaintext
    4. Sign the hash using owner's RSA private key (RSA-PSS)
    5. Encrypt the AES key with owner's RSA public key (RSA-OAEP)
    6. Optionally encrypt PDF password for later use
    7. Store all components in the database
    8. Create an audit log entry
    
    Args:
        db: Database session
        owner: User who owns the document
        filename: Original filename (sanitized)
        content_type: MIME type of the document
        plaintext: Document content in bytes
        private_key_pem: Owner's RSA private key in PEM format
        pdf_password: Optional password for PDF protection
        
    Returns:
        Created Document object with all encrypted fields populated
        
    Security Notes:
        - AES key is unique per document
        - Plaintext is never stored
        - Signature provides authenticity and non-repudiation
        - GCM mode provides authenticated encryption
        - PDF password is encrypted with AES-256-GCM
    """
    # Generate unique AES key
    aes_key = crypto.generate_aes_key()
    
    # Encrypt document
    ciphertext, nonce, tag = crypto.encrypt_document(plaintext, aes_key)
    
    # Create hash and sign
    doc_hash = crypto.hash_bytes(plaintext)
    signature = crypto.sign_hash(doc_hash, private_key_pem)
    
    # Encrypt AES key for owner
    encrypted_key_for_owner = crypto.encrypt_aes_key_for_public_key(aes_key, owner.public_key_pem)
    
    # Encrypt PDF password if provided
    pdf_password_encrypted = None
    has_pdf_password = False
    if pdf_password:
        # Encrypt PDF password using same AES key (separate nonce/tag)
        pdf_pass_bytes = pdf_password.encode('utf-8')
        pdf_enc, pdf_nonce, pdf_tag = crypto.encrypt_document(pdf_pass_bytes, aes_key)
        # Store as: nonce(16) + tag(16) + ciphertext
        pdf_password_encrypted = pdf_nonce + pdf_tag + pdf_enc
        has_pdf_password = True
    
    doc = Document(
        owner_id=owner.id,
        filename=filename,
        content_type=content_type,
        encrypted_content=ciphertext,
        nonce=nonce,
        tag=tag,
        doc_hash=doc_hash,
        signature=signature,
        aes_key_encrypted_owner=encrypted_key_for_owner,
        pdf_password_encrypted=pdf_password_encrypted,
        has_pdf_password=has_pdf_password,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    
    log_msg = f"Uploaded {filename}"
    if has_pdf_password:
        log_msg += " (with PDF password protection)"
    create_audit_log(db, owner.id, "document.upload", "document", doc.id, log_msg)
    
    return doc


def list_documents_for_user(db: Session, user: User) -> Iterable[Document]:
    """
    List all documents accessible to a user.
    
    Returns documents that the user either:
    - Owns (created/uploaded)
    - Has been granted access to (via sharing)
    
    Args:
        db: Database session
        user: User to list documents for
        
    Returns:
        List of Document objects ordered by creation date (newest first)
    """
    owned = db.query(Document).filter(Document.owner_id == user.id)
    shared_ids = db.query(DocumentShare.document_id).filter(DocumentShare.recipient_id == user.id)
    shared = db.query(Document).filter(Document.id.in_(shared_ids))
    return owned.union(shared).order_by(Document.created_at.desc()).all()


def get_document(db: Session, document_id: int) -> Optional[Document]:
    """Retrieve a document by its ID.
    
    Args:
        db: Database session
        document_id: Unique document identifier
        
    Returns:
        Document object if found, None otherwise
    """
    return db.query(Document).filter(Document.id == document_id).first()


def decrypt_and_verify_document(
    doc: Document, user: User, private_key_pem: str, db: Session
) -> tuple[bytes, bool, bool]:
    """
    Decrypt a document and verify its digital signature.
    
    This function performs the following operations:
    1. Determine if user is owner or has shared access
    2. Retrieve the appropriate encrypted AES key
    3. Decrypt the AES key using user's RSA private key
    4. Decrypt the document content using the AES key
    5. Compute hash of decrypted content
    6. Verify digital signature against owner's public key
    7. Check for tampering by comparing hashes
    8. Create an audit log entry
    
    Args:
        doc: Document to decrypt and verify
        user: User requesting access
        private_key_pem: User's RSA private key in PEM format
        db: Database session
        
    Returns:
        Tuple of (plaintext, verified, tampered) where:
        - plaintext: Decrypted document content as bytes
        - verified: True if signature is valid AND content not tampered
        - tampered: True if computed hash doesn't match stored hash
        
    Raises:
        ValueError: If user doesn't have access to the document
        
    Security Notes:
        - Access control is enforced (owner or shared recipient only)
        - Signature verification uses owner's public key (not user's)
        - Both signature and hash must be valid for verification to pass
    """
    # Get encrypted AES key
    if doc.owner_id == user.id:
        encrypted_key = doc.aes_key_encrypted_owner
    else:
        share = get_share(db, doc.id, user.id)
        if not share:
            raise ValueError("Access denied")
        encrypted_key = share.encrypted_aes_key
    
    # Decrypt AES key and document
    aes_key = crypto.decrypt_aes_key_with_private_key(encrypted_key, private_key_pem)
    plaintext = crypto.decrypt_document(doc.encrypted_content, doc.nonce, doc.tag, aes_key)
    
    # Verify signature
    computed_hash = crypto.hash_bytes(plaintext)
    sig_valid = crypto.verify_signature(computed_hash, doc.signature, doc.owner.public_key_pem)
    tampered = computed_hash != doc.doc_hash
    
    create_audit_log(db, user.id, "document.access", "document", doc.id, f"Accessed {doc.filename}")
    
    return plaintext, sig_valid and not tampered, tampered


def decrypt_and_prepare_download(
    doc: Document, user: User, private_key_pem: str, db: Session, pdf_password: Optional[str] = None
) -> tuple[bytes, bool, bool, str]:
    """
    Decrypt document and apply PDF password protection if applicable.
    
    Args:
        doc: Document to prepare for download
        user: User requesting download
        private_key_pem: User's RSA private key
        db: Database session
        pdf_password: Password to decrypt stored PDF password (if has_pdf_password=True)
        
    Returns:
        Tuple of (content, verified, tampered, error_message)
        
    Raises:
        ValueError: If access denied or PDF password required but not provided
    """
    # Decrypt and verify document
    plaintext, verified, tampered = decrypt_and_verify_document(doc, user, private_key_pem, db)
    
    # If document has PDF password protection
    if doc.has_pdf_password:
        if not pdf_password:
            raise ValueError("File password required for this document")
        
        # Decrypt stored PDF password
        try:
            # Get AES key
            if doc.owner_id == user.id:
                encrypted_key = doc.aes_key_encrypted_owner
            else:
                share = get_share(db, doc.id, user.id)
                if not share:
                    raise ValueError("Access denied")
                encrypted_key = share.encrypted_aes_key
            
            aes_key = crypto.decrypt_aes_key_with_private_key(encrypted_key, private_key_pem)
            
            # Decrypt PDF password (format: nonce(16) + tag(16) + ciphertext)
            if doc.pdf_password_encrypted:
                pdf_nonce = doc.pdf_password_encrypted[:16]
                pdf_tag = doc.pdf_password_encrypted[16:32]
                pdf_enc = doc.pdf_password_encrypted[32:]
                stored_pdf_password = crypto.decrypt_document(pdf_enc, pdf_nonce, pdf_tag, aes_key).decode('utf-8')
                
                # Verify provided password matches
                if pdf_password != stored_pdf_password:
                    raise ValueError("Incorrect file password")
        except Exception as e:
            raise ValueError(f"Failed to decrypt file password: {str(e)}")
        
        # Apply password protection to file (works for ALL file types using ZIP)
        try:
            # Wrap file in password-protected ZIP
            plaintext = pdf_protection.protect_file(plaintext, pdf_password, doc.filename)
            
            create_audit_log(
                db, user.id, "document.download", "document", doc.id, 
                f"Downloaded {doc.filename} (password-protected ZIP)"
            )
        except Exception as e:
            # If protection fails, return original content with warning
            create_audit_log(
                db, user.id, "document.download", "document", doc.id,
                f"Downloaded {doc.filename} (password protection failed: {str(e)})"
            )
    else:
        create_audit_log(
            db, user.id, "document.download", "document", doc.id,
            f"Downloaded {doc.filename}"
        )
    
    error_msg = ""
    if tampered:
        error_msg = "WARNING: Document has been tampered with!"
    elif not verified:
        error_msg = "WARNING: Signature verification failed!"
    
    return plaintext, verified, tampered, error_msg


def delete_document(db: Session, document: Document, user_id: int) -> None:
    """
    Delete a document (owner only).
    
    Args:
        db: Database session
        document: Document to delete
        user_id: ID of user performing deletion (for audit log)
        
    Note:
        Caller must verify that user is the document owner before calling.
        All associated shares are automatically deleted via cascade.
    """
    db.delete(document)
    db.commit()
    create_audit_log(db, user_id, "document.delete", "document", document.id, f"Deleted {document.filename}")


def get_share(db: Session, document_id: int, recipient_id: int) -> Optional[DocumentShare]:
    """
    Check if a document is shared with a specific recipient.
    
    Args:
        db: Database session
        document_id: ID of the document
        recipient_id: ID of the potential recipient
        
    Returns:
        DocumentShare object if document is shared with recipient, None otherwise
    """
    return (
        db.query(DocumentShare)
        .filter(DocumentShare.document_id == document_id, DocumentShare.recipient_id == recipient_id)
        .first()
    )
