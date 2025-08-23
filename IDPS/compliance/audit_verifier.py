import os
import json
import hashlib
import logging
from datetime import timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from config import BASE_DIR

logger = logging.getLogger(__name__)

class AuditVerifier:
    def __init__(self, encryption_key=None):
        """
        Initialize the AuditVerifier with an optional encryption key.
        If none is provided, tries to load from AUDIT_LOG_KEY or the keyfile.
        """
        self.log_dir = os.path.join(BASE_DIR, 'audit_logs')
        if encryption_key is not None:
            if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
                raise ValueError("Encryption key must be 32 bytes")
            self.encryption_key = encryption_key
        else:
            self.encryption_key = self._load_key()

    def _keyfile_path(self):
        secrets_dir = os.path.join(BASE_DIR, ".secrets")
        return os.path.join(secrets_dir, "audit_key.bin")

    def _load_key(self):
        # 1) Environment variable
        env = os.environ.get("AUDIT_LOG_KEY")
        if env:
            try:
                if all(c in "0123456789abcdefABCDEF" for c in env) and len(env) in (64, 66):
                    key = bytes.fromhex(env)
                else:
                    import base64
                    key = base64.b64decode(env)
                if len(key) == 32:
                    logger.info("Loaded encryption key from AUDIT_LOG_KEY")
                    return key
            except Exception as e:
                logger.error(f"Failed to decode AUDIT_LOG_KEY: {e}")

        # 2) Key file
        path = self._keyfile_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                key = f.read()
            if len(key) == 32:
                logger.info(f"Loaded encryption key from {path}")
                return key

        raise ValueError("No valid encryption key found (set AUDIT_LOG_KEY or ensure keyfile exists)")

    def _decrypt_entry(self, entry):
        if not isinstance(entry, dict):
            raise ValueError("Entry must be a dictionary")

        required_fields = {'nonce', 'ciphertext', 'tag'}
        if not all(field in entry for field in required_fields):
            raise ValueError(f"Missing required fields in entry. Required: {required_fields}")

        try:
            nonce = bytes.fromhex(entry['nonce'])
            ciphertext = bytes.fromhex(entry['ciphertext'])
            tag = bytes.fromhex(entry['tag'])

            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(plaintext.decode('utf-8'))

        except InvalidTag as e:
            logger.error("Decryption failed - invalid authentication tag (wrong key?)")
            raise
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise