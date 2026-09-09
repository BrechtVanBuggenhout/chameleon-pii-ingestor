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