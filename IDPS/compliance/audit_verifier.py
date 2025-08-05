import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import BASE_DIR

class AuditVerifier:
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key
        self.log_dir = os.path.join(BASE_DIR, 'audit_logs')
    
    def _decrypt_entry(self, encrypted_entry):
        """Decrypt an audit log entry"""
        nonce = bytes.fromhex(encrypted_entry['nonce'])
        ciphertext = bytes.fromhex(encrypted_entry['ciphertext'])
        tag = bytes.fromhex(encrypted_entry['tag'])
        
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return json.loads(plaintext.decode())
    
    def verify_log_file(self, log_path):
        """Verify integrity of a log file and decrypt its contents"""
        verified_entries = []
        previous_hash = "0" * 64  # Genesis hash for header
        
        with open(log_path, 'r') as f:
            for line in f:
                parts = line.strip().split('|', 1)
                if len(parts) != 2:
                    raise ValueError("Invalid log entry format")
                
                entry_hash, entry_json = parts
                # Verify hash chain
                computed_hash = hashlib.sha256(
                    (previous_hash + entry_json).encode()
                ).hexdigest()
                
                if computed_hash != entry_hash:
                    raise ValueError(f"Hash mismatch at entry: {entry_json}")
                
                # Decrypt entry
                encrypted_entry = json.loads(entry_json)
                decrypted_entry = self._decrypt_entry(encrypted_entry)
                
                # Add to results
                verified_entries.append(decrypted_entry)
                previous_hash = entry_hash
        
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
