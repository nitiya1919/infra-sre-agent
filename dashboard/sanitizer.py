import re

# Comprehensive regex patterns for sensitive data
SENSITIVE_PATTERNS = [
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
    Scrub sensitive tokens, credentials, connection strings, and keys 
    from raw log payloads and stack traces before LLM transmission.
    """
    if not raw_text:
        return ""
    
    sanitized = raw_text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
    return sanitized
