import re

SENSITIVE_PATTERNS = [
    # IPv4 Addresses (e.g., 54.164.150.193 -> [REDACTED_IP])
    (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', '[REDACTED_IP]'),

    # Database Connection Strings (e.g., postgresql://user:password@host:port/db)
    (r'(postgres(?:ql)?|mysql|mongodb|redis|amqp):\/\/([^:\s]+):([^@\s]+)@([^\/\s]+)', r'\1://\2:***REDACTED***@\4'),
    
    # Generic passwords, secrets, tokens in key-value pairs
    (r'(password|passwd|secret|api_key|token|auth|bearer)\s*[:=]\s*([^\s,]+)', r'\1=***REDACTED***'),
    
    # JWT / Bearer Tokens
    (r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 'Bearer ***REDACTED_JWT***'),
    
    # AWS Access Keys / Secret Keys
    (r'(AKIA[0-9A-Z]{16})', '***REDACTED_AWS_KEY***'),
    (r'(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{40})', r'\1***REDACTED_SECRET***'),
    
    # Private SSH / TLS Keys
    (r'-----BEGIN (?:RSA|OPENSSH|PRIVATE) PRIVATE KEY-----(?:.|\n)*?-----END (?:RSA|OPENSSH|PRIVATE) PRIVATE KEY-----', '***REDACTED_PRIVATE_KEY***'),
]

def sanitize_log_payload(raw_text: str) -> str:
    """
    Scrub sensitive tokens, credentials, IPs, connection strings, and keys 
    from raw log payloads and stack traces before DB storage or LLM transmission.
    """
    if not raw_text:
        return ""
    
    sanitized = str(raw_text)
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
    return sanitized
