from app import crypto


def test_rsa_keypair_generation():
    """Test RSA key pair generation."""
    public, private = crypto.generate_rsa_keypair(2048)
    assert "BEGIN PUBLIC KEY" in public
    assert "BEGIN PRIVATE KEY" in private


def test_rsa_encrypt_decrypt_aes_key():
    """Test RSA encryption/decryption of AES keys."""
    public, private = crypto.generate_rsa_keypair()
    key = crypto.generate_aes_key()
    encrypted = crypto.encrypt_aes_key_for_public_key(key, public)
    decrypted = crypto.decrypt_aes_key_with_private_key(encrypted, private)
    assert key == decrypted


def test_aes_encrypt_decrypt_roundtrip():
    """Test AES-256-GCM encryption/decryption."""
    key = crypto.generate_aes_key()
    plaintext = b"hello secure world"
    ciphertext, nonce, tag = crypto.encrypt_document(plaintext, key)
    recovered = crypto.decrypt_document(ciphertext, nonce, tag, key)
    assert recovered == plaintext


def test_sign_verify():
    """Test RSA-PSS digital signature."""
    public, private = crypto.generate_rsa_keypair()
    data_hash = crypto.hash_bytes(b"data")
    signature = crypto.sign_hash(data_hash, private)
    assert crypto.verify_signature(data_hash, signature, public)


def test_sign_verify_tampered():
    """Test signature verification fails for tampered data."""
    public, private = crypto.generate_rsa_keypair()
    data_hash = crypto.hash_bytes(b"data")
    signature = crypto.sign_hash(data_hash, private)
    tampered_hash = crypto.hash_bytes(b"tampered")
    assert not crypto.verify_signature(tampered_hash, signature, public)


def test_private_key_encryption():
    """Test private key encryption with password."""
    _, private = crypto.generate_rsa_keypair()
    password = "StrongPass123"
    encrypted = crypto.encrypt_private_key(private, password)
    decrypted = crypto.decrypt_private_key(encrypted, password)
    assert decrypted == private
