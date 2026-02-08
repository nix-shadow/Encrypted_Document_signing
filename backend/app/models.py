from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, LargeBinary, String, Text, JSON
from sqlalchemy.orm import relationship
import enum

from .db import Base


class UserRole(enum.Enum):
    """User role types"""
    ADMIN = "admin"
    USER = "user"


class ApprovalStatus(enum.Enum):
    """Status for various approval workflows"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    public_key_pem = Column(Text, nullable=False)
    private_key_encrypted = Column(LargeBinary, nullable=False)
    role = Column(String(20), default='user', nullable=False)
    is_approved = Column(Boolean, default=False, nullable=False)  # Admin approval required
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    documents = relationship("Document", back_populates="owner", cascade="all, delete")
    shares_received = relationship("DocumentShare", back_populates="recipient", cascade="all, delete")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete")
    trusted_devices = relationship("TrustedDevice", back_populates="user", cascade="all, delete")
    mfa_secret = relationship("MFASecret", back_populates="user", uselist=False, cascade="all, delete")
    pending_device_auths = relationship("PendingDeviceAuth", back_populates="user", foreign_keys="[PendingDeviceAuth.user_id]", cascade="all, delete")
    pending_logins = relationship("PendingLogin", back_populates="user", foreign_keys="[PendingLogin.user_id]", cascade="all, delete")
    viewing_sessions = relationship("ViewingSession", back_populates="user", foreign_keys="[ViewingSession.user_id]", cascade="all, delete")


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(128), nullable=False)
    encrypted_content = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    tag = Column(LargeBinary, nullable=False)
    doc_hash = Column(LargeBinary, nullable=False)
    signature = Column(LargeBinary, nullable=False)
    aes_key_encrypted_owner = Column(LargeBinary, nullable=False)
    pdf_password_encrypted = Column(LargeBinary, nullable=True)  # Optional PDF password (encrypted with AES)
    has_pdf_password = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    owner = relationship("User", back_populates="documents")
    shares = relationship("DocumentShare", back_populates="document", cascade="all, delete")


class DocumentShare(Base):
    __tablename__ = "document_shares"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    encrypted_aes_key = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    document = relationship("Document", back_populates="shares")
    recipient = relationship("User", back_populates="shares_received")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    action = Column(String(128), nullable=False)
    entity_type = Column(String(128), nullable=False)
    entity_id = Column(Integer, nullable=True)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")


class TrustedDevice(Base):
    """Store authorized devices for each user to prevent unauthorized access."""
    __tablename__ = "trusted_devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_fingerprint = Column(String(255), nullable=False)
    device_name = Column(String(255))
    user_agent = Column(Text)
    ip_address = Column(String(45))
    is_trusted = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="trusted_devices")


class MFASecret(Base):
    """Store TOTP secrets for two-factor authentication."""
    __tablename__ = "mfa_secrets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    secret = Column(String(32), nullable=False)
    is_enabled = Column(Boolean, default=False)
    backup_codes = Column(JSON, nullable=True)  # Store as JSON array for SQLite compatibility
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="mfa_secret")


class PendingDeviceAuth(Base):
    """Temporary tokens for authorizing new devices."""
    __tablename__ = "pending_device_auth"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_fingerprint = Column(String(255), nullable=False)
    device_name = Column(String(255))
    user_agent = Column(Text)
    ip_address = Column(String(45))
    auth_token = Column(String(64), nullable=False, unique=True)
    status = Column(String(20), default='pending', nullable=False)
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="pending_device_auths", foreign_keys=[user_id])


class PendingLogin(Base):
    """Track login attempts pending admin approval."""
    __tablename__ = "pending_logins"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_fingerprint = Column(String(255), nullable=False)
    device_name = Column(String(255))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    status = Column(String(20), default='pending', nullable=False)
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="pending_logins", foreign_keys=[user_id])


class ViewingSession(Base):
    """Track active document viewing sessions."""
    __tablename__ = "viewing_sessions"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_fingerprint = Column(String(255), nullable=False)
    device_name = Column(String(255))
    ip_address = Column(String(45))
    status = Column(String(20), default='pending', nullable=False)
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_active_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="viewing_sessions", foreign_keys=[user_id])
    document = relationship("Document")
