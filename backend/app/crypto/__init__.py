"""Cryptography module for encryption, signing, and key management."""

from .aes_encryption import decrypt_document, encrypt_document, generate_aes_key
from .digital_signature import sign_hash, verify_signature
from .hash_utils import hash_bytes, hash_string
from .key_manager import decrypt_private_key, encrypt_private_key
from .rsa_operations import (
    decrypt_aes_key_with_private_key,
    encrypt_aes_key_for_public_key,
    generate_rsa_keypair,
)

__all__ = [
    "generate_aes_key",
    "encrypt_document",
    "decrypt_document",
    "generate_rsa_keypair",
    "encrypt_aes_key_for_public_key",
    "decrypt_aes_key_with_private_key",
    "sign_hash",
    "verify_signature",
    "hash_bytes",
    "hash_string",
    "encrypt_private_key",
    "decrypt_private_key",
]
