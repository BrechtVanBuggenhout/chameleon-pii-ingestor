import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from typing import Dict, Any

class CertificateVerifier:
    """
    Utility to validate RSA-PSS signatures on Certificates of Destruction.
    """
    def __init__(self, public_key_pem: bytes):
        self.public_key = serialization.load_pem_public_key(public_key_pem)

    def verify_certificate(self, certificate: Dict[str, Any]) -> bool:
        """
        Verifies the 'signature' field against the 'body' of the certificate.
        """
        try:
            # Extract signature and the original data that was signed
            signature_b64 = certificate.get("signature")
            body = certificate.get("body")
            
            if not signature_b64 or not body:
                return False

            signature = base64.b64decode(signature_b64)
            # Ensure deterministic JSON string representation for verification
            message = json.dumps(body, sort_keys=True).encode('utf-8')

            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False