"""
Audit logging service module.

This module provides functions for creating and retrieving audit logs,
enabling security monitoring and compliance tracking.
"""

from typing import Optional

from sqlalchemy.orm import Session

from ..models import AuditLog, User


def create_audit_log(
    db: Session,
    user_id: Optional[int],
    action: str,
    entity_type: str,
    entity_id: Optional[int],
    detail: Optional[str] = None,
) -> AuditLog:
    """
    Create an audit log entry for security and compliance tracking.
    
    Audit logs record all significant actions in the system for:
    - Security incident investigation
    - Compliance auditing
    - User activity monitoring
    - Forensic analysis
    
    Args:
        db: Database session
        user_id: ID of user performing the action (None for system actions)
        action: Action type (e.g., 'auth.login', 'document.upload', 'document.share')
        entity_type: Type of entity affected (e.g., 'user', 'document')
        entity_id: ID of the affected entity
        detail: Optional human-readable description
        
    Returns:
        Created AuditLog object with timestamp
        
    Common Actions:
        - auth.login, auth.logout, auth.register
        - user.password_change
        - document.upload, document.access, document.delete
        - document.share, document.revoke
    """
    log = AuditLog(user_id=user_id, action=action, entity_type=entity_type, entity_id=entity_id, detail=detail)
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_audit_logs(db: Session, user: User, limit: int = 50):
    """
    Retrieve audit logs for a specific user.
    
    Args:
        db: Database session
        user: User to retrieve logs for
        limit: Maximum number of logs to return (default 50)
        
    Returns:
        List of AuditLog objects ordered by timestamp (newest first)
    """
    return db.query(AuditLog).filter(AuditLog.user_id == user.id).order_by(AuditLog.created_at.desc()).limit(limit).all()


def get_user_audit_logs(db: Session, user_id: int, limit: int = 50):
    """
    Retrieve audit logs for a specific user ID with serialization.
    
    Args:
        db: Database session
        user_id: User ID to retrieve logs for
        limit: Maximum number of logs to return (default 50)
        
    Returns:
        List of dictionaries with audit log data
    """
    logs = db.query(AuditLog).filter(
        AuditLog.user_id == user_id
    ).order_by(AuditLog.created_at.desc()).limit(limit).all()
    
    return [{
        "id": log.id,
        "action": log.action,
        "entity_type": log.entity_type,
        "entity_id": log.entity_id,
        "detail": log.detail,
        "created_at": log.created_at
    } for log in logs]
