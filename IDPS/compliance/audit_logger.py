import csv
import hashlib
import json
import os
import threading
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys
import base64
import stat

# Import config with error handling
try:
    from config import BASE_DIR, GDPR_COMPLIANCE
except ImportError:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    GDPR_COMPLIANCE = False

class AuditLogger:
    # Class-level encryption key storage
    _encryption_key = None
    _key_lock = threading.Lock()

    # ---------- NEW: key loading/persistence helpers ----------
    @staticmethod
    def _secrets_dir():
        path = os.path.join(BASE_DIR, ".secrets")
        os.makedirs(path, exist_ok=True)
        return path

    @classmethod
    def _keyfile_path(cls):
        return os.path.join(cls._secrets_dir(), "audit_key.bin")

    @classmethod
    def _load_key_from_env(cls):
        val = os.environ.get("AUDIT_LOG_KEY")
        if not val:
            return None
        try:
            # hex?
            if all(c in "0123456789abcdefABCDEF" for c in val) and len(val) in (64, 66):
                b = bytes.fromhex(val)
            else:
                b = base64.b64decode(val)
            return b if len(b) == 32 else None
        except Exception:
            return None

    @classmethod
    def _load_or_create_keyfile(cls):
        path = cls._keyfile_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                b = f.read()
            if len(b) == 32:
                return b
        # create new 32-byte key
        b = os.urandom(32)
        with open(path, "wb") as f:
            f.write(b)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        return b
    # ----------------------------------------------------------

    @classmethod
    def get_encryption_key(cls):
        """Stable key across processes: ENV -> keyfile -> create+persist."""
        with cls._key_lock:
            if cls._encryption_key is not None:
                return cls._encryption_key
            env_key = cls._load_key_from_env()
            if env_key:
                cls._encryption_key = env_key
                return cls._encryption_key
            cls._encryption_key = cls._load_or_create_keyfile()
            return cls._encryption_key

    @classmethod
    def set_encryption_key(cls, key):
        """Set and persist the key (updates keyfile)."""
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Encryption key must be 32 bytes")
        with cls._key_lock:
            cls._encryption_key = key
            path = cls._keyfile_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(key)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    def __init__(self, test_mode=False, test_name=None, encryption_key=None):
        self.test_mode = test_mode
        self.test_name = test_name
        self.current_log_date = datetime.utcnow().date()
        self.log_queue = []
        self.lock = threading.Lock()
        self.running = True

        # Set up log directory based on mode
        if test_mode and test_name:
            self.log_dir = os.path.join(BASE_DIR, 'results', f'{test_name}_logs')
        else:
            self.log_dir = os.path.join(BASE_DIR, 'audit_logs')
        os.makedirs(self.log_dir, exist_ok=True)

        # Set encryption key - use provided key, class key, or generate/load one
        self.encryption_key = encryption_key if encryption_key is not None else self.get_encryption_key()

        # Initialize current log file
        self.log_file = self._get_log_file_path()
        self._initialize_log_file()

        # Start the processing thread after everything is initialized
        self.logger_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.logger_thread.start()

    def _generate_encryption_key(self):
        """Kept for compatibility (returns the stable key)."""
        return self.get_encryption_key()

    def _get_log_file_path(self):
        """Get path for current log file based on date and test mode."""
        if self.test_mode and self.test_name:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            return os.path.join(self.log_dir, f"{self.test_name}_{timestamp}.enc")
        else:
            date_str = self.current_log_date.strftime("%Y-%m-%d")
            return os.path.join(self.log_dir, f"audit_log_{date_str}.enc")

    def _initialize_log_file(self):
        """Create new log file with header (includes key_id)."""
        if not os.path.exists(self.log_file):
            key_id = hashlib.sha256(self.encryption_key).hexdigest()[:16]
            header = {
                "system": "IoT IDPS",
                "version": "1.0",
                "creation_date": datetime.utcnow().isoformat(),
                "encryption": "AES-GCM",
                "hash_algorithm": "SHA-256",
                "key_id": key_id
            }
            self._append_log_entry(header, is_header=True)

    def _encrypt_data(self, data):
        """Encrypt data using AES-GCM authenticated encryption."""
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json.dumps(data).encode()) + encryptor.finalize()
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": encryptor.tag.hex()}

    def _append_log_entry(self, entry, is_header=False):
        """Append encrypted entry to log file with hash chaining."""
        encrypted_entry = self._encrypt_data(entry)

        # Previous hash (genesis for header)
        if is_header:
            previous_hash = "0" * 64
        else:
            try:
                with open(self.log_file, 'rb') as f:
                    previous_line = list(f)[-1].decode().strip()
                    previous_hash = previous_line.split('|')[0]
            except (IndexError, FileNotFoundError):
                previous_hash = "0" * 64

        entry_str = json.dumps(encrypted_entry)
        new_hash = hashlib.sha256((previous_hash + entry_str).encode()).hexdigest()

        with open(self.log_file, 'a') as f:
            f.write(f"{new_hash}|{entry_str}\n")

    def log_event(self, event_type, source_ip=None, action=None, confidence=None,
                  details=None, description=None, severity=None, duration=None):
        """Add an audit event to the log queue."""
        # Handle new format with description and severity
        if description is not None:
            details = details or {}
            if isinstance(details, str):
                details = {"message": details}
            elif not isinstance(details, dict):
                details = {}
            if description:
                details["message"] = str(description)
            if duration is not None:
                details["duration_seconds"] = float(duration)
            action = str(action or event_type)
            source_ip = str(source_ip or "test_runner")
            if severity:
                severity = str(severity).lower()
                confidence = {'high': 0.9, 'medium': 0.6, 'low': 0.3}.get(severity, 0.5)

        # Anonymize IP if required by GDPR
        if GDPR_COMPLIANCE and source_ip:
            try:
                from .anonymizer import anonymize_ip
                source_ip = anonymize_ip(source_ip)
            except ImportError:
                pass

        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event_type": str(event_type),
            "source_ip": str(source_ip or "system"),
            "action": str(action or "unknown"),
            "confidence": float(confidence or 0.5),
            "details": details or {}
        }

        with self.lock:
            self.log_queue.append(log_entry)

    def _process_queue(self):
        """Process log entries in background thread."""
        while self.running or self.log_queue:
            current_date = datetime.utcnow().date()
            if current_date != self.current_log_date:
                self.current_log_date = current_date
                self.log_file = self._get_log_file_path()
                self._initialize_log_file()

            with self.lock:
                if self.log_queue:
                    entry = self.log_queue.pop(0)
                    try:
                        self._append_log_entry(entry)
                    except Exception as e:
                        print(f"[!] Error writing to audit log: {e}", file=sys.stderr)
                else:
                    time.sleep(0.1)

    def finalize(self):
        """Finalize logging and process any remaining entries."""
        while self.log_queue:
            try:
                entry = self.log_queue.pop(0)
                self._append_log_entry(entry)
            except IndexError:
                break
            except Exception as e:
                print(f"[!] Error finalizing audit log: {e}", file=sys.stderr)

    def shutdown(self):
        """Shutdown the logger gracefully."""
        self.running = False
        if hasattr(self, 'logger_thread') and self.logger_thread.is_alive():
            self.logger_thread.join(timeout=5)
        self.finalize()

# Singleton logger instance
audit_logger = AuditLogger()
