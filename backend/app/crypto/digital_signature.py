from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def sign_hash(hash_bytes_value: bytes, private_key_pem: str) -> bytes:
    """
    Sign a hash using RSA private key (RSA-PSS).
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return private_key.sign(
        hash_bytes_value,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(hash_bytes_value: bytes, signature: bytes, public_key_pem: str) -> bool:
    """
    Verify RSA-PSS signature using public key.
    Returns True if valid, False otherwise.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        public_key.verify(
            signature,
            hash_bytes_value,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
