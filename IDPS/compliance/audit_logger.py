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

# Import config with error handling
try:
    from config import BASE_DIR, GDPR_COMPLIANCE
except ImportError:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    GDPR_COMPLIANCE = False

class AuditLogger:
    def __init__(self, test_mode=False, test_name=None):
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
        
        # Generate encryption key (in production, use secure key management)
        self.encryption_key = self._generate_encryption_key()
        
        # Initialize current log file
        self.log_file = self._get_log_file_path()
        self._initialize_log_file()
        
        # Start the processing thread after everything is initialized
        self.logger_thread = threading.Thread(target=self._process_queue)
        self.logger_thread.daemon = True
        self.logger_thread.start()
    
    def _generate_encryption_key(self):
        """Generate a secure encryption key (AES-256)"""
        return os.urandom(32)
    
    def _get_log_file_path(self):
        """Get path for current log file based on date and test mode"""
        if self.test_mode and self.test_name:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            return os.path.join(self.log_dir, f"{self.test_name}_{timestamp}.enc")
        else:
            date_str = self.current_log_date.strftime("%Y-%m-%d")
            return os.path.join(self.log_dir, f"audit_log_{date_str}.enc")
    
    def _initialize_log_file(self):
        """Create new log file with header"""
        if not os.path.exists(self.log_file):
            header = {
                "system": "IoT IDPS",
                "version": "1.0",
                "creation_date": datetime.utcnow().isoformat(),
                "encryption": "AES-GCM",
                "hash_algorithm": "SHA-256"
            }
            self._append_log_entry(header, is_header=True)
    
    def _encrypt_data(self, data):
        """Encrypt data using AES-GCM authenticated encryption"""
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Convert data to JSON string
        json_data = json.dumps(data)
        ciphertext = encryptor.update(json_data.encode()) + encryptor.finalize()
        
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": encryptor.tag.hex()
        }
    
    def _append_log_entry(self, entry, is_header=False):
        """Append encrypted entry to log file"""
        encrypted_entry = self._encrypt_data(entry)
        
        # Create hash chain for integrity verification
        if is_header:
            previous_hash = "0" * 64  # Genesis hash
        else:
            try:
                with open(self.log_file, 'rb') as f:
                    previous_line = list(f)[-1].decode().strip()
                    previous_hash = previous_line.split('|')[0]
            except (IndexError, FileNotFoundError):
                previous_hash = "0" * 64
        
        # Create new hash
        entry_str = json.dumps(encrypted_entry)
        new_hash = hashlib.sha256(
            (previous_hash + entry_str).encode()
        ).hexdigest()
        
        # Write to log file
        with open(self.log_file, 'a') as f:
            f.write(f"{new_hash}|{entry_str}\n")
    
    def log_event(self, event_type, source_ip=None, action=None, confidence=None, 
                 details=None, description=None, severity=None, duration=None):
        """
        Add an audit event to the log queue
        
        Args:
            event_type: Type of the event (e.g., 'test_start', 'attack_detected')
            source_ip: Source IP address (default: None)
            action: Action taken (default: None)
            confidence: Confidence level (0.0-1.0)
            details: Additional details as dict
            description: Human-readable description (alternative to details)
            severity: Severity level ('low', 'medium', 'high')
            duration: Duration in seconds (for timing events)
        """
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
                confidence = {
                    'high': 0.9, 
                    'medium': 0.6, 
                    'low': 0.3
                }.get(severity, 0.5)
        
        # Anonymize IP if required by GDPR
        if GDPR_COMPLIANCE and source_ip:
            try:
                from .anonymizer import anonymize_ip
                source_ip = anonymize_ip(source_ip)
            except ImportError:
                pass  # If anonymizer is not available, log as is
        
        # Create the log entry
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event_type": str(event_type),
            "source_ip": str(source_ip or "system"),
            "action": str(action or "unknown"),
            "confidence": float(confidence or 0.5),
            "details": details or {}
        }
        
        # Add to queue in a thread-safe manner
        with self.lock:
            self.log_queue.append(log_entry)
    
    def _process_queue(self):
        """Process log entries in background thread"""
        while self.running or self.log_queue:
            # Check if we need to rotate log file
            current_date = datetime.utcnow().date()
            if current_date != self.current_log_date:
                self.current_log_date = current_date
                self.log_file = self._get_log_file_path()
                self._initialize_log_file()
            
            # Process entries in queue
            with self.lock:
                if self.log_queue:
                    entry = self.log_queue.pop(0)
                    try:
                        self._append_log_entry(entry)
                    except Exception as e:
                        print(f"[!] Error writing to audit log: {e}", file=sys.stderr)
                else:
                    time.sleep(0.1)  # Avoid busy waiting
    
    def finalize(self):
        """Finalize logging and process any remaining entries"""
        # Process remaining entries
        while self.log_queue:
            try:
                entry = self.log_queue.pop(0)
                self._append_log_entry(entry)
            except IndexError:
                break
            except Exception as e:
                print(f"[!] Error finalizing audit log: {e}", file=sys.stderr)
    
    def shutdown(self):
        """Shutdown the logger gracefully"""
        self.running = False
        if hasattr(self, 'logger_thread') and self.logger_thread.is_alive():
            self.logger_thread.join(timeout=5)
        self.finalize()

# Singleton logger instance
audit_logger = AuditLogger()
