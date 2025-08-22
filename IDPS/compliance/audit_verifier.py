import os
import json
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from config import BASE_DIR

# Configure logging
logger = logging.getLogger(__name__)

class AuditVerifier:
    def __init__(self, encryption_key=None):
        """
        Initialize the AuditVerifier with an optional encryption key.
        If no key is provided, it will try to use the default key from AuditLogger.
        """
        self.encryption_key = encryption_key
        self.log_dir = os.path.join(BASE_DIR, 'audit_logs')
        
        # Set default key if not provided
        if not self.encryption_key:
            self._set_default_key()
    
    def _set_default_key(self):
        """Set the default encryption key from AuditLogger"""
        try:
            from .audit_logger import AuditLogger
            # Create a temporary logger to get the key
            temp_logger = AuditLogger()
            self.encryption_key = temp_logger._generate_encryption_key()
            logger.info("Using default encryption key from AuditLogger")
        except Exception as e:
            logger.error(f"Failed to get encryption key from AuditLogger: {e}")
            raise ValueError("Encryption key is required and could not be obtained from AuditLogger")
    
    def _decrypt_entry(self, entry):
        """
        Decrypt a single log entry.
        
        Args:
            entry (dict): The encrypted log entry with 'nonce', 'ciphertext', and 'tag' keys
            
        Returns:
            dict: The decrypted log entry
            
        Raises:
            ValueError: If decryption fails or the entry is invalid
        """
        if not isinstance(entry, dict):
            raise ValueError("Entry must be a dictionary")
            
        required_fields = {'nonce', 'ciphertext', 'tag'}
        if not all(field in entry for field in required_fields):
            raise ValueError(f"Missing required fields in entry. Required: {required_fields}")
        
        try:
            # Convert hex strings to bytes
            nonce = bytes.fromhex(entry['nonce'])
            ciphertext = bytes.fromhex(entry['ciphertext'])
            tag = bytes.fromhex(entry['tag'])
            
            # Set up the cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            
            # Decrypt the data
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Parse the JSON data
            try:
                return json.loads(plaintext.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse decrypted JSON: {e}")
                raise ValueError("Invalid JSON in decrypted data")
                
        except InvalidTag as e:
            logger.error("Decryption failed - invalid authentication tag")
            raise ValueError("Decryption failed - invalid authentication tag") from e
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError(f"Decryption failed: {str(e)}") from e
    
    def verify_log_file(self, log_path):
        """
        Verify and decrypt a log file.
        
        Args:
            log_path (str): Path to the log file to verify
            
        Returns:
            list: List of verified and decrypted log entries
            
        Raises:
            FileNotFoundError: If the log file doesn't exist
            ValueError: If the log file is invalid or corrupted
        """
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log file not found: {log_path}")
        
        verified_entries = []
        previous_hash = "0" * 64  # Initial hash for the first entry
        
        try:
            with open(log_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        # Split the line into hash and JSON parts
                        parts = line.split('|', 1)
                        if len(parts) != 2:
                            logger.warning(f"Invalid log format at line {line_num}: expected 'hash|json'")
                            continue
                            
                        entry_hash, entry_json = parts
                        
                        # Verify the hash chain
                        computed_hash = hashlib.sha256(
                            (previous_hash + entry_json).encode('utf-8')
                        ).hexdigest()
                        
                        if computed_hash != entry_hash:
                            logger.warning(f"Hash mismatch at line {line_num}")
                            continue
                        
                        try:
                            # Parse the JSON data
                            entry_data = json.loads(entry_json)
                            
                            # Decrypt the entry if it's encrypted
                            if all(key in entry_data for key in ['nonce', 'ciphertext', 'tag']):
                                decrypted_entry = self._decrypt_entry(entry_data)
                                verified_entries.append(decrypted_entry)
                            else:
                                # If not encrypted, just add the entry
                                verified_entries.append(entry_data)
                                
                            # Update the previous hash for the next iteration
                            previous_hash = entry_hash
                            
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid JSON at line {line_num}: {e}")
                            continue
                            
                    except Exception as e:
                        logger.error(f"Error processing line {line_num}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to process log file: {e}")
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
