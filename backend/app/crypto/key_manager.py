import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using Scrypt KDF."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def encrypt_private_key(private_key_pem: str, password: str) -> bytes:
    """
    Encrypt user's private RSA key with password-derived key.
    Returns: salt + nonce + encrypted_key
    """
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, private_key_pem.encode(), None)
    return salt + nonce + encrypted


def decrypt_private_key(encrypted_blob: bytes, password: str) -> str:
    """
    Decrypt user's private RSA key using password.
    Raises exception if password is incorrect.
    """
    salt, nonce, encrypted = encrypted_blob[:16], encrypted_blob[16:28], encrypted_blob[28:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    return decrypted.decode()
