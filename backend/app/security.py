import secrets
import time
from typing import Dict, Optional

from passlib.context import CryptContext

from .config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


class SessionData:
    def __init__(self, user_id: int, private_key_pem: str, issued_at: float):
        self.user_id = user_id
        self.private_key_pem = private_key_pem
        self.issued_at = issued_at


class SessionManager:
    def __init__(self, max_age_seconds: int):
        self.max_age_seconds = max_age_seconds
        self.sessions: Dict[str, SessionData] = {}
        self.login_attempts: Dict[str, list[float]] = {}

    def create_session(self, user_id: int, private_key_pem: str) -> str:
        token = secrets.token_urlsafe(32)
        self.sessions[token] = SessionData(user_id=user_id, private_key_pem=private_key_pem, issued_at=time.time())
        return token

    def get_session(self, token: str) -> Optional[SessionData]:
        data = self.sessions.get(token)
        if not data:
            return None
        if time.time() - data.issued_at > self.max_age_seconds:
            self.sessions.pop(token, None)
            return None
        return data

    def destroy_session(self, token: str) -> None:
        self.sessions.pop(token, None)

    def record_login_attempt(self, email: str) -> None:
        attempts = self.login_attempts.setdefault(email, [])
        now = time.time()
        # keep only last minute
        attempts[:] = [t for t in attempts if now - t < 60]
        attempts.append(now)

    def too_many_attempts(self, email: str) -> bool:
        attempts = self.login_attempts.get(email, [])
        now = time.time()
        attempts = [t for t in attempts if now - t < 60]
        self.login_attempts[email] = attempts
        return len(attempts) >= settings.rate_limit_per_minute


session_manager = SessionManager(max_age_seconds=settings.session_max_age_seconds)


def hash_password(password: str) -> str:
    """
    Hash password using bcrypt.
    Bcrypt has a 72-byte limit, so we truncate if necessary.
    """
    # Truncate to 72 bytes if needed (keep as string for passlib)
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        # Decode back to string after truncating to 72 bytes
        password = password_bytes[:72].decode('utf-8', errors='ignore')
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify password against bcrypt hash.
    Applies same truncation as hash_password.
    """
    # Truncate to 72 bytes if needed (keep as string for passlib)
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        # Decode back to string after truncating to 72 bytes
        password = password_bytes[:72].decode('utf-8', errors='ignore')
    return pwd_context.verify(password, hashed)
