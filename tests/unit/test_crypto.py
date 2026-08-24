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


class TestEncryptFieldBundle:
    """The canonical key_id:iv_b64:ciphertext_b64 bundle format -- extracted
    from what used to be two byte-for-byte-identical private copies
    (ingestion.py's _encrypt_field, pii_vault_sync.py's _encrypt_field) into
    the one real implementation, since a third caller (pubsub ingest) was
    about to become a third copy."""

    def _context(self):
        return {"dek": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "key_id": "v2"}

    def test_produces_the_key_id_colon_iv_colon_ciphertext_format(self):
        bundle = ChameleonCrypto.encrypt_field_bundle(self._context(), "user-1", "hello@example.com")
        parts = bundle.decode("utf-8").split(":")
        assert len(parts) == 3
        key_id, iv_b64, ciphertext_b64 = parts
        assert key_id == "v2"
        assert len(base64.b64decode(iv_b64)) == 12  # AES-GCM's standard 96-bit nonce
        assert len(base64.b64decode(ciphertext_b64)) > 0

    def test_the_bundle_decrypts_back_to_the_original_value(self):
        context = self._context()
        value = "hello@example.com"
        bundle = ChameleonCrypto.encrypt_field_bundle(context, "user-1", value)

        key_id, iv_b64, ciphertext_b64 = bundle.decode("utf-8").split(":")
        raw_payload_b64 = base64.b64encode(base64.b64decode(iv_b64) + base64.b64decode(ciphertext_b64)).decode("utf-8")
        decrypted = ChameleonCrypto.decrypt(context["dek"], "user-1", raw_payload_b64)

        assert decrypted == value

    def test_uses_a_fresh_random_iv_per_call(self):
        context = self._context()
        bundle1 = ChameleonCrypto.encrypt_field_bundle(context, "user-1", "same-value")
        bundle2 = ChameleonCrypto.encrypt_field_bundle(context, "user-1", "same-value")
        assert bundle1 != bundle2

    def test_ingestion_and_pii_vault_sync_both_call_the_shared_implementation(self):
        # Regression guard for the extraction itself: confirms neither
        # module still carries its own duplicate implementation.
        from app.pipelines import ingestion
        from app.scanners import pii_vault_sync

        assert not hasattr(ingestion.IngestionPipeline, "_encrypt_field")
        assert not hasattr(pii_vault_sync.PiiVaultSyncJob, "_encrypt_field")