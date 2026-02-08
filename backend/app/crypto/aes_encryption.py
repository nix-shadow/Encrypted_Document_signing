import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return secrets.token_bytes(32)


def encrypt_document(plaintext: bytes, aes_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt document using AES-256-GCM.
    Returns (ciphertext, nonce, tag).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    return ciphertext, nonce, tag


def decrypt_document(ciphertext: bytes, nonce: bytes, tag: bytes, aes_key: bytes) -> bytes:
    """
    Decrypt document using AES-256-GCM.
    Raises exception if authentication fails (tampered data).
    """
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
