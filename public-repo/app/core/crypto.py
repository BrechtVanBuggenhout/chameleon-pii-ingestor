import hashlib
import hmac
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional

class ChameleonCrypto:
    """
    Implements Randomized AES-256-GCM and Deterministic Tokenization 
    as required by Project Chameleon v2.
    """

    @staticmethod
    def encrypt(dek_hex: str, user_id: str, plaintext: str, iv: Optional[bytes] = None) -> str:
        key = bytes.fromhex(dek_hex)
        aesgcm = AESGCM(key)
        
        # Use provided IV or generate a random 12-byte nonce for security.
        nonce = iv if iv is not None else os.urandom(12)
        
        # Requirement: AAD is the userId string
        aad = user_id.encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)
        
        # Package IV + Ciphertext together before encoding.
        # This allows decryption without needing to derive the IV deterministically.
        payload = nonce + ciphertext
        return base64.b64encode(payload).decode('utf-8')

    @staticmethod
    def decrypt(dek_hex: str, user_id: str, payload_b64: str) -> str:
        key = bytes.fromhex(dek_hex)
        aesgcm = AESGCM(key)
        aad = user_id.encode()
        
        raw_payload = base64.b64decode(payload_b64)
        
        # Extract the IV (first 12 bytes) and the actual ciphertext.
        iv = raw_payload[:12]
        ciphertext = raw_payload[12:]
        
        decrypted = aesgcm.decrypt(iv, ciphertext, aad)
        return decrypted.decode('utf-8')

    @staticmethod
    def generate_token(token_key_hex: str, plaintext: str) -> str:
        """
        Generates a deterministic HMAC-SHA256 token for joins and analytics.
        """
        key = bytes.fromhex(token_key_hex)
        h = hmac.new(key, plaintext.encode(), hashlib.sha256)
        return h.hexdigest()

    @staticmethod
    def encrypt_field_bundle(context: dict, user_id: str, value: str) -> bytes:
        """
        The canonical `key_id:iv_b64:ciphertext_b64` bundle format used
        everywhere pii_vault's `encrypted_value` column (or an equivalent,
        e.g. raw_users.encrypted_pii) is written -- ingestion.py,
        pii_vault_sync.py, and the pubsub ingest path all need byte-
        identical output so anything that decrypts one can decrypt any of
        them. Was duplicated (byte-for-byte) in ingestion.py and
        pii_vault_sync.py before this; extracted here as the single real
        implementation rather than adding a third copy.

        Fresh random IV per call (`encrypt`'s own default) -- safe to call
        once per declared field for the same user/DEK, same reasoning as
        every existing call site already relied on.
        """
        iv = os.urandom(12)
        raw_bundle_b64 = ChameleonCrypto.encrypt(context["dek"], user_id, value, iv=iv)
        raw_bundle = base64.b64decode(raw_bundle_b64)
        ciphertext_only = raw_bundle[12:]
        iv_b64 = base64.b64encode(iv).decode("utf-8")
        ciphertext_b64 = base64.b64encode(ciphertext_only).decode("utf-8")
        return f"{context['key_id']}:{iv_b64}:{ciphertext_b64}".encode("utf-8")