import re
from typing import Optional


def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_password(password: str) -> tuple[bool, Optional[str]]:
    """
    Validate password strength.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain digit"
    return True, None


def validate_file_type(filename: str, content_type: str) -> tuple[bool, Optional[str]]:
    """
    Validate uploaded file type.
    Allowed: PDF, DOCX, TXT, images.
    """
    allowed_types = {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain",
        "image/jpeg",
        "image/png",
        "image/gif",
    }
    
    allowed_extensions = {".pdf", ".docx", ".txt", ".jpg", ".jpeg", ".png", ".gif"}
    
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    
    if content_type not in allowed_types and ext not in allowed_extensions:
        return False, "File type not allowed"
    
    return True, None


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    # Remove path components
    filename = filename.split("/")[-1].split("\\")[-1]
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)
    return filename[:255]  # Limit length
