"""
Multi-Factor Authentication utilities using TOTP (Time-based One-Time Password).
Supports Google Authenticator, Authy, and other TOTP-compatible apps.
"""
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64
from typing import List, Tuple


def generate_mfa_secret() -> str:
    """
    Generate a new base32-encoded secret for TOTP.
    
    Returns:
        str: Base32-encoded secret (16 bytes = ~26 characters)
    """
    return pyotp.random_base32()


def generate_qr_code(username: str, secret: str, issuer: str = "SecureDoc") -> str:
    """
    Generate a QR code for TOTP enrollment.
    
    Args:
        username: User's email or username
        secret: Base32-encoded TOTP secret
        issuer: Application name (displayed in authenticator app)
    
    Returns:
        str: Base64-encoded PNG image of QR code
    """
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode()
    
    return f"data:image/png;base64,{img_base64}"


def verify_totp_token(secret: str, token: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP token against the secret.
    
    Args:
        secret: Base32-encoded TOTP secret
        token: 6-digit TOTP code from user
        valid_window: Number of 30-second windows to check (1 = ±30s, 2 = ±60s)
    
    Returns:
        bool: True if token is valid, False otherwise
    """
    if not token or not secret:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=valid_window)


def generate_backup_codes(count: int = 10) -> List[str]:
    """
    Generate backup recovery codes for MFA.
    Each code is 8 characters (alphanumeric, uppercase).
    
    Args:
        count: Number of backup codes to generate
    
    Returns:
        List of backup codes formatted as XXXX-XXXX
    """
    codes = []
    for _ in range(count):
        # Generate 8 random bytes, convert to hex (16 chars), take first 8
        raw_code = secrets.token_hex(4).upper()
        # Format as XXXX-XXXX
        formatted = f"{raw_code[:4]}-{raw_code[4:]}"
        codes.append(formatted)
    return codes


def verify_backup_code(stored_codes: List[str], input_code: str) -> Tuple[bool, List[str]]:
    """
    Verify a backup code and remove it from the list (single-use).
    
    Args:
        stored_codes: List of remaining backup codes
        input_code: Code provided by user
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, remaining_codes)
    """
    if not input_code or not stored_codes:
        return False, stored_codes
    
    # Normalize input (remove spaces, hyphens, uppercase)
    normalized_input = input_code.replace("-", "").replace(" ", "").upper()
    
    for i, code in enumerate(stored_codes):
        normalized_stored = code.replace("-", "").replace(" ", "").upper()
        if normalized_input == normalized_stored:
            # Valid code - remove it from list
            remaining = stored_codes[:i] + stored_codes[i+1:]
            return True, remaining
    
    return False, stored_codes


def get_current_totp_token(secret: str) -> str:
    """
    Get the current TOTP token (for testing purposes only).
    
    Args:
        secret: Base32-encoded TOTP secret
    
    Returns:
        str: Current 6-digit TOTP code
    """
    totp = pyotp.TOTP(secret)
    return totp.now()
