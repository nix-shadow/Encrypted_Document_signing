from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    public_key_pem: str
    role: str
    created_at: datetime

    class Config:
        orm_mode = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class DocumentMeta(BaseModel):
    id: int
    filename: str
    content_type: str
    created_at: datetime
    owner_id: int
    has_pdf_password: bool = False

    class Config:
        orm_mode = True


class DocumentResponse(BaseModel):
    id: int
    filename: str
    content_type: str
    created_at: datetime
    owner_id: int
    verified: bool
    tampered: bool
    content_b64: str


class ShareRequest(BaseModel):
    recipient_email: EmailStr


class ShareDocumentRequest(BaseModel):
    document_id: int
    recipient_email: EmailStr


class ShareInfo(BaseModel):
    share_id: int
    document_id: int
    document_name: str
    recipient_email: EmailStr
    recipient_name: str
    shared_at: datetime


class MessageResponse(BaseModel):
    message: str


class AuditEntry(BaseModel):
    id: int
    action: str
    entity_type: str
    entity_id: Optional[int]
    detail: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


class AuditList(BaseModel):
    entries: List[AuditEntry]


# MFA Schemas
class MFAEnrollResponse(BaseModel):
    secret: str
    qr_code: str  # Base64 data URL
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    token: str


class MFAStatusResponse(BaseModel):
    enabled: bool
    backup_codes_remaining: Optional[int] = None


# Device Management Schemas
class DeviceInfo(BaseModel):
    id: int
    device_name: str
    device_fingerprint: str
    ip_address: str
    is_trusted: bool
    is_active: bool
    last_used_at: datetime
    created_at: datetime

    class Config:
        orm_mode = True


class DeviceListResponse(BaseModel):
    devices: List[DeviceInfo]


class DeviceAuthRequest(BaseModel):
    auth_token: str


class LoginWithDeviceRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_token: Optional[str] = None  # Required if MFA is enabled


class DownloadRequest(BaseModel):
    pdf_password: Optional[str] = None  # Required if document has PDF password


# Admin Schemas
class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = "user"  # "admin" or "user"


class AdminUserResponse(BaseModel):
    id: int
    email: str
    role: str
    is_approved: bool
    approved_at: Optional[datetime]
    created_at: datetime

    class Config:
        orm_mode = True


class PendingLoginResponse(BaseModel):
    id: int
    user_id: int
    user_email: str
    device_name: str
    ip_address: str
    status: str
    created_at: datetime

    class Config:
        orm_mode = True


class PendingDeviceResponse(BaseModel):
    id: int
    user_id: int
    user_email: str
    device_name: str
    device_fingerprint: str
    ip_address: str
    status: str
    created_at: datetime

    class Config:
        orm_mode = True


class ViewingSessionResponse(BaseModel):
    id: int
    user_id: int
    user_email: str
    device_name: str
    ip_address: str
    status: str
    started_at: datetime
    last_active_at: datetime

    class Config:
        orm_mode = True


class ApprovalRequest(BaseModel):
    approve: bool  # True to approve, False to reject


class LoginPollResponse(BaseModel):
    status: str  # "pending", "approved", "rejected"
    message: str
    session_token: Optional[str] = None
