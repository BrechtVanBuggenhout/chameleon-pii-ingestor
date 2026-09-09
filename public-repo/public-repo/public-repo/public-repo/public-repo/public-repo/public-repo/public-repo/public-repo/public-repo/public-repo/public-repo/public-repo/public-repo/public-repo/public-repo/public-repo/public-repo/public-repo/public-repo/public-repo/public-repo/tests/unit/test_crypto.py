import pytest
from app.core.crypto import ChameleonCrypto
import base64

def test_iv_is_randomized():
    """v2 Requirement: Ensures encryption is randomized even for the same user/data."""
    user_id = "user_123"
    dek = "0" * 64
    plaintext = "test-data"
    
    c1 = ChameleonCrypto.encrypt(dek, user_id, plaintext)
    c2 = ChameleonCrypto.encrypt(dek, user_id, plaintext)
    
    # With random IVs, ciphertexts should never be identical
    assert c1 != c2

def test_encryption_cycle():
    """Tests that we can encrypt and decrypt data successfully."""
    dek = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" # 32 bytes hex
    user_id = "user_123"
    plaintext = "hello@project-chameleon.io"
    
    ciphertext = ChameleonCrypto.encrypt(dek, user_id, plaintext)
    decrypted = ChameleonCrypto.decrypt(dek, user_id, ciphertext)
    
    assert decrypted == plaintext
    assert ciphertext != plaintext

def test_token_is_deterministic():
    """
    Verifies that HMAC tokens remain deterministic for joins/analytics.
    """
    token_key = "f" * 64
    data = "secret-payload"
    
    t1 = ChameleonCrypto.generate_token(token_key, data)
    t2 = ChameleonCrypto.generate_token(token_key, data)
    
    assert t1 == t2
    assert len(t1) == 64 # Hex SHA256