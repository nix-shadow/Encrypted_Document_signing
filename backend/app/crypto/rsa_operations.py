from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """
    Generate RSA key pair.
    Returns (public_key_pem, private_key_pem) as strings.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_pem.decode(), private_pem.decode()


def encrypt_aes_key_for_public_key(aes_key: bytes, public_key_pem: str) -> bytes:
    """
    Encrypt AES key using recipient's RSA public key (RSA-OAEP).
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def decrypt_aes_key_with_private_key(encrypted_key: bytes, private_key_pem: str) -> bytes:
    """
    Decrypt AES key using user's RSA private key (RSA-OAEP).
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
