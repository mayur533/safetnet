import re
import html
import bleach
from django.utils.html import strip_tags
from django.core.exceptions import ValidationError
import logging

logger = logging.getLogger(__name__)

# Allowed HTML tags for rich text fields
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
ALLOWED_ATTRIBUTES = {}

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)',
    r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
    r'(\b(OR|AND)\s+[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]?)',
    r'(\bUNION\s+SELECT\b)',
    r'(\bDROP\s+TABLE\b)',
    r'(\bINSERT\s+INTO\b)',
    r'(\bDELETE\s+FROM\b)',
    r'(\bUPDATE\s+\w+\s+SET\b)',
]

# XSS patterns
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'on\w+\s*=',
    r'<iframe[^>]*>',
    r'<object[^>]*>',
    r'<embed[^>]*>',
    r'<link[^>]*>',
    r'<meta[^>]*>',
    r'<style[^>]*>',
    r'expression\s*\(',
    r'url\s*\(',
]


def sanitize_string(value, max_length=None, allow_html=False):
    """
    Sanitize a string input to prevent XSS and SQL injection attacks.
    
    Args:
        value: The string to sanitize
        max_length: Maximum allowed length
        allow_html: Whether to allow HTML tags
    
    Returns:
        Sanitized string
    
    Raises:
        ValidationError: If the input contains malicious content
    """
    if not isinstance(value, str):
        return value
    
    # Check for SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            logger.warning(f"SQL injection attempt detected: {value[:100]}")
            raise ValidationError("Invalid input detected.")
    
    # Check for XSS patterns
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            logger.warning(f"XSS attempt detected: {value[:100]}")
            raise ValidationError("Invalid input detected.")
    
    # HTML sanitization
    if allow_html:
        # Use bleach to sanitize HTML
        value = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
    else:
        # Strip all HTML tags
        value = strip_tags(value)
        # HTML escape remaining content
        value = html.escape(value)
    
    # Length validation
    if max_length and len(value) > max_length:
        raise ValidationError(f"Input too long. Maximum length is {max_length} characters.")
    
    return value.strip()


def sanitize_json_field(value):
    """
    Sanitize JSON field content.
    
    Args:
        value: JSON data to sanitize
    
    Returns:
        Sanitized JSON data
    """
    if not isinstance(value, dict):
        return value
    
    sanitized = {}
    for key, val in value.items():
        # Sanitize keys
        sanitized_key = sanitize_string(str(key), max_length=100)
        
        # Sanitize values based on type
        if isinstance(val, str):
            sanitized[sanitized_key] = sanitize_string(val, max_length=1000)
        elif isinstance(val, dict):
            sanitized[sanitized_key] = sanitize_json_field(val)
        elif isinstance(val, list):
            sanitized[sanitized_key] = [
                sanitize_string(item, max_length=1000) if isinstance(item, str) else item
                for item in val
            ]
        else:
            sanitized[sanitized_key] = val
    
    return sanitized


def validate_email(email):
    """
    Validate and sanitize email address.
    
    Args:
        email: Email address to validate
    
    Returns:
        Sanitized email address
    
    Raises:
        ValidationError: If email is invalid
    """
    if not email:
        return email
    
    email = sanitize_string(email, max_length=254)
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise ValidationError("Invalid email format.")
    
    return email.lower()


def validate_username(username):
    """
    Validate and sanitize username.
    
    Args:
        username: Username to validate
    
    Returns:
        Sanitized username
    
    Raises:
        ValidationError: If username is invalid
    """
    if not username:
        raise ValidationError("Username is required.")
    
    username = sanitize_string(username, max_length=150)
    
    # Username validation rules
    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters long.")
    
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        raise ValidationError("Username can only contain letters, numbers, dots, underscores, and hyphens.")
    
    if username.startswith('.') or username.endswith('.'):
        raise ValidationError("Username cannot start or end with a dot.")
    
    return username


def validate_password_strength(password):
    """
    Validate password strength.
    
    Args:
        password: Password to validate
    
    Raises:
        ValidationError: If password doesn't meet strength requirements
    """
    if not password:
        raise ValidationError("Password is required.")
    
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    
    if not re.search(r'[a-z]', password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    
    if not re.search(r'\d', password):
        raise ValidationError("Password must contain at least one digit.")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError("Password must contain at least one special character.")
    
    # Check for common weak passwords
    weak_passwords = ['password', '123456', 'admin', 'qwerty', 'letmein']
    if password.lower() in weak_passwords:
        raise ValidationError("Password is too common. Please choose a stronger password.")


def sanitize_file_upload(filename):
    """
    Sanitize uploaded file filename.
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    
    Raises:
        ValidationError: If filename is invalid
    """
    if not filename:
        raise ValidationError("Filename is required.")
    
    # Remove path components
    filename = filename.split('/')[-1].split('\\')[-1]
    
    # Sanitize filename
    filename = sanitize_string(filename, max_length=255)
    
    # Check for valid file extension
    allowed_extensions = ['.csv', '.json', '.txt', '.pdf', '.xlsx']
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        raise ValidationError(f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}")
    
    return filename
