import hashlib

def anonymize_ip(ip_address):
    """GDPR-compliant IP anonymization"""
    if not ip_address:
        return "0.0.0.0"
    
    # Preserve local network structure
    if ip_address.startswith('192.168.'):
        parts = ip_address.split('.')
        return f"192.168.x.x"
    
    # Full anonymization for public IPs
    return hashlib.sha256(ip_address.encode()).hexdigest()[:8]