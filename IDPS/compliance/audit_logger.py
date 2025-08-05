import csv
import hashlib
import json
import os
import threading
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import BASE_DIR, GDPR_COMPLIANCE
import logging

class AuditLogger:
    def __init__(self):
        self.log_queue = []
        self.lock = threading.Lock()
        self.running = True
        self.logger_thread = threading.Thread(target=self._process_queue)
        self.logger_thread.daemon = True
        self.logger_thread.start()
        
        # Create secure log directory
        self.log_dir = os.path.join(BASE_DIR, 'audit_logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Generate encryption key (in production, use secure key management)
        self.encryption_key = self._generate_encryption_key()
        
        # Initialize current log file
        self.current_log_date = datetime.utcnow().date()
        self.log_file = self._get_log_file_path()
        self._initialize_log_file()
    
    def _generate_encryption_key(self):
        """Generate a secure encryption key (AES-256)"""
        # In production, this should come from a secure key management system
        return os.urandom(32)
    
    def _get_log_file_path(self):
        """Get path for current log file based on date"""
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
            with open(self.log_file, 'rb') as f:
                previous_line = list(f)[-1].decode().strip()
                previous_hash = previous_line.split('|')[0]
        
        # Create new hash
        entry_str = json.dumps(encrypted_entry)
        new_hash = hashlib.sha256(
            (previous_hash + entry_str).encode()
        ).hexdigest()
        
        # Write to log file
        with open(self.log_file, 'a') as f:
            f.write(f"{new_hash}|{entry_str}\n")
    
    def log_event(self, event_type, source_ip, action, confidence=None, details=None):
        """Add an audit event to the log queue"""
        # Anonymize IP if required by GDPR
        if GDPR_COMPLIANCE:
            from .anonymizer import anonymize_ip
            source_ip = anonymize_ip(source_ip)
        
        timestamp = datetime.utcnow().isoformat()
        
        with self.lock:
            self.log_queue.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "source_ip": source_ip,
                "action": action,
                "confidence": confidence,
                "details": details
            })
    
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
                    self._append_log_entry(entry)
                else:
                    time.sleep(0.1)  # Avoid busy waiting
    
    def finalize(self):
        """Shutdown logger gracefully"""
        self.running = False
        self.logger_thread.join(timeout=5)
        
        # Process any remaining entries
        while self.log_queue:
            entry = self.log_queue.pop(0)
            self._append_log_entry(entry)

# Singleton logger instance
audit_logger = AuditLogger()
