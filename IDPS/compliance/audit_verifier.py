import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from config import BASE_DIR
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuditVerifier:
    def __init__(self, encryption_key=None):
        """
        Initialize the AuditVerifier
        
        Args:
            encryption_key: Optional key for decryption. If None, will try to use the same key as AuditLogger
        """
        if encryption_key is None:
            # Try to use the same key as AuditLogger
            try:
                from .audit_logger import AuditLogger
                dummy_logger = AuditLogger()
                self.encryption_key = dummy_logger._generate_encryption_key()
                logger.info("Using default encryption key from AuditLogger")
            except Exception as e:
                logger.error(f"Failed to get encryption key from AuditLogger: {e}")
                raise ValueError("Encryption key is required")
        else:
            self.encryption_key = encryption_key
            
        self.log_dir = os.path.join(BASE_DIR, 'audit_logs')
    
    def _decrypt_entry(self, encrypted_entry):
        """
        Decrypt an audit log entry
        
        Args:
            encrypted_entry: Dictionary containing 'nonce', 'ciphertext', and 'tag'
            
        Returns:
            dict: Decrypted log entry
            
        Raises:
            ValueError: If decryption fails or entry is invalid
        """
        try:
            nonce = bytes.fromhex(encrypted_entry.get('nonce', ''))
            ciphertext = bytes.fromhex(encrypted_entry.get('ciphertext', ''))
            tag = bytes.fromhex(encrypted_entry.get('tag', ''))
            
            if not all([nonce, ciphertext, tag]):
                raise ValueError("Missing required fields in encrypted entry")
                
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                return json.loads(plaintext.decode('utf-8'))
            except (ValueError, json.JSONDecodeError) as e:
                logger.error(f"Failed to decode decrypted data: {e}")
                raise ValueError("Invalid decrypted data format")
                
        except InvalidTag as e:
            logger.error(f"Decryption failed - invalid tag: {e}")
            raise ValueError("Decryption failed - invalid authentication tag")
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def verify_log_file(self, log_path):
        """
        Verify integrity of a log file and decrypt its contents
        
        Args:
            log_path: Path to the log file to verify and decrypt
            
        Returns:
            list: List of verified and decrypted log entries
            
        Raises:
            FileNotFoundError: If log file doesn't exist
            ValueError: If log file is invalid or corrupted
        """
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log file not found: {log_path}")
            
        verified_entries = []
        previous_hash = "0" * 64  # Genesis hash for header
        line_number = 0
        
        try:
            with open(log_path, 'r') as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        parts = line.split('|', 1)
                        if len(parts) != 2:
                            logger.warning(f"Invalid log entry format at line {line_number}")
                            continue
                            
                        entry_hash, entry_json = parts
                        
                        # Verify hash chain
                        computed_hash = hashlib.sha256(
                            (previous_hash + entry_json).encode('utf-8')
                        ).hexdigest()
                        
                        if computed_hash != entry_hash:
                            logger.warning(f"Hash mismatch at line {line_number}")
                            continue
                        
                        # Decrypt entry
                        try:
                            encrypted_entry = json.loads(entry_json)
                            decrypted_entry = self._decrypt_entry(encrypted_entry)
                            verified_entries.append(decrypted_entry)
                            previous_hash = entry_hash
                        except json.JSONDecodeError:
                            logger.error(f"Invalid JSON at line {line_number}")
                            continue
                            
                    except Exception as e:
                        logger.error(f"Error processing line {line_number}: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to process log file: {str(e)}")
            raise ValueError(f"Log file processing failed: {str(e)}")
        
        return verified_entries
    
    def export_to_csv(self, log_date, output_path):
        """Export a day's audit log to GDPR-compliant CSV"""
        log_path = os.path.join(self.log_dir, f"audit_log_{log_date}.enc")
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"No log file for date {log_date}")
        
        entries = self.verify_log_file(log_path)
        
        # Filter out header
        entries = [e for e in entries if 'timestamp' in e]
        
        # Write to CSV
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'timestamp', 'event_type', 'source_ip', 'action', 
                'confidence', 'details'
            ])
            writer.writeheader()
            writer.writerows(entries)
    
    def search_logs(self, start_date, end_date, event_type=None, source_ip=None):
        """Search logs within a date range"""
        results = []
        current_date = start_date
        
        while current_date <= end_date:
            log_path = os.path.join(
                self.log_dir, 
                f"audit_log_{current_date.strftime('%Y-%m-%d')}.enc"
            )
            
            if os.path.exists(log_path):
                try:
                    entries = self.verify_log_file(log_path)
                    # Filter out header
                    entries = [e for e in entries if 'timestamp' in e]
                    
                    # Apply filters
                    for entry in entries:
                        if event_type and entry['event_type'] != event_type:
                            continue
                        if source_ip and entry['source_ip'] != source_ip:
                            continue
                        results.append(entry)
                except Exception as e:
                    logging.error(f"Error processing log {log_path}: {str(e)}")
            
            current_date += timedelta(days=1)
        
        return results
