"""Service layer for business logic."""

from .audit_service import create_audit_log, get_audit_logs
from .document_service import (
    create_document,
    decrypt_and_verify_document,
    decrypt_and_prepare_download,
    delete_document,
    get_document,
    list_documents_for_user,
)
from .share_service import list_shares, revoke_share, share_document
from .user_service import change_password, create_user, get_user_by_email, get_user_by_id

__all__ = [
    "create_user",
    "get_user_by_email",
    "get_user_by_id",
    "change_password",
    "create_document",
    "list_documents_for_user",
    "get_document",
    "decrypt_and_verify_document",
    "decrypt_and_prepare_download",
    "delete_document",
    "share_document",
    "revoke_share",
    "list_shares",
    "create_audit_log",
    "get_audit_logs",
]
