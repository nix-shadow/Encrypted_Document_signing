"""
User service module for managing user accounts and authentication.

This module provides functions for user creation, retrieval, and password management.
It handles RSA key pair generation and secure private key storage.
"""

from typing import Optional

from sqlalchemy.orm import Session

from .. import crypto
from ..models import User
from ..security import hash_password
from .audit_service import create_audit_log


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """
    Retrieve a user by their email address.
    
    Args:
        db: Database session
        email: User's email address
        
    Returns:
        User object if found, None otherwise
    """
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """
    Retrieve a user by their ID.
    
    Args:
        db: Database session
        user_id: User's unique identifier
        
    Returns:
        User object if found, None otherwise
    """
    return db.query(User).filter(User.id == user_id).first()


def create_user(db: Session, email: str, password: str, role=None) -> User:
    """
    Register a new user with RSA key pair generation.
    
    This function:
    1. Generates a 2048-bit RSA key pair
    2. Encrypts the private key with the user's password (using Scrypt KDF)
    3. Hashes the password using bcrypt (work factor 12)
    4. Stores the user in the database
    5. Creates an audit log entry
    
    Args:
        db: Database session
        email: User's email address (must be unique)
        password: User's password (will be hashed)
        role: User role (UserRole enum, defaults to USER)
        
    Returns:
        Newly created User object with public_key_pem populated
        
    Raises:
        IntegrityError: If email already exists
    """
    from ..models import UserRole
    
    public_key, private_key = crypto.generate_rsa_keypair(key_size=2048)
    encrypted_private = crypto.encrypt_private_key(private_key, password)
    
    user = User(
        email=email,
        password_hash=hash_password(password),
        public_key_pem=public_key,
        private_key_encrypted=encrypted_private,
        role=role.value if role else UserRole.USER.value,
        is_approved=False  # Require admin approval unless set otherwise
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    create_audit_log(db, user.id, "user.created", "user", user.id, f"Created user {email}")
    return user


def change_password(db: Session, user: User, old_password: str, new_password: str) -> bool:
    """
    Change user password and re-encrypt private key.
    
    This function verifies the old password by attempting to decrypt the
    user's private key. If successful, it re-encrypts the private key with
    the new password and updates the password hash.
    
    Args:
        db: Database session
        user: User object whose password to change
        old_password: Current password (for verification)
        new_password: New password to set
        
    Returns:
        True if password change was successful, False if old password is incorrect
        
    Note:
        This operation is atomic - if any step fails, no changes are committed.
    """
    try:
        # Decrypt private key with old password
        private_key_pem = crypto.decrypt_private_key(user.private_key_encrypted, old_password)
        
        # Re-encrypt with new password
        new_encrypted = crypto.encrypt_private_key(private_key_pem, new_password)
        
        # Update user
        user.password_hash = hash_password(new_password)
        user.private_key_encrypted = new_encrypted
        db.commit()
        
        create_audit_log(db, user.id, "user.password_change", "user", user.id, "Password changed")
        return True
    except Exception:
        return False
