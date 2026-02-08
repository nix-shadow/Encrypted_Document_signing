from hashlib import sha256


def hash_bytes(data: bytes) -> bytes:
    """Create SHA-256 hash of data."""
    return sha256(data).digest()


def hash_string(text: str) -> bytes:
    """Create SHA-256 hash of string."""
    return sha256(text.encode()).digest()
