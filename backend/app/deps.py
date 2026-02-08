from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from . import security
from .db import get_db
from .models import User, UserRole


SESSION_COOKIE_NAME = "session_token"


def get_current_session_token(session_token: str | None = Cookie(default=None)) -> str:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return session_token


def get_current_user(
    db: Session = Depends(get_db), session_token: str = Depends(get_current_session_token)
) -> tuple[User, str]:
    session_data = security.session_manager.get_session(session_token)
    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")
    user = db.query(User).filter(User.id == session_data.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    # Check if user is approved (admin bypass)
    if user.role != 'admin' and not user.is_approved:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account pending admin approval")
    
    return user, session_data.private_key_pem


def get_admin_user(
    db: Session = Depends(get_db), session_token: str = Depends(get_current_session_token)
) -> tuple[User, str]:
    """Dependency to ensure current user is an admin."""
    user, private_key = get_current_user(db, session_token)
    if user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user, private_key
