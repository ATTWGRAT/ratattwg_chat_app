"""Input validation functions for secure user registration."""

import re
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from Crypto.PublicKey import ECC

# Initialize Argon2 hasher for validation
ph = PasswordHasher()


def validate_email(email):
    """
    Validate email format.
    
    Args:
        email: Email string to validate
        
    Returns:
        bool: True if valid email format
    """
    if not email or not isinstance(email, str):
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_username(username):
    """
    Validate username: max 24 chars, alphanumeric, underscore, hyphen only.
    
    Args:
        username: Username string to validate
        
    Returns:
        bool: True if valid username
    """
    if not username or not isinstance(username, str):
        return False
    if len(username) > 24:
        return False
    pattern = r'^[a-zA-Z0-9_-]+$'
    return re.match(pattern, username) is not None


def validate_argon2_hash(password_hash):
    """
    Validate Argon2ID hash format or raw hash output.
    
    Accepts either:
    - Full Argon2ID format: $argon2id$v=19$m=16384,t=2,p=1$salt$hash
    - Raw hash output: 64 hex characters (for zero-knowledge with hidden salt)
    
    Args:
        password_hash: Argon2 hash string or raw hash hex to validate
        
    Returns:
        bool: True if valid Argon2ID hash or raw hash
    """
    if not password_hash or not isinstance(password_hash, str):
        return False
    
    # Check if it's a raw hex hash (64 chars = 32 bytes)
    if len(password_hash) == 64:
        try:
            bytes.fromhex(password_hash)
            return True
        except ValueError:
            pass
    
    # Check if it's a full Argon2ID hash
    try:
        # Check if it's a valid Argon2ID hash
        if not password_hash.startswith('$argon2id$'):
            return False
        # Try to verify format by parsing with dummy password
        ph.verify(password_hash, 'dummy')
    except VerifyMismatchError:
        # Hash is valid format but doesn't match dummy password (expected)
        return True
    except (InvalidHashError, Exception):
        return False
    return True


def validate_aes_iv(iv_hex):
    """
    Validate AES IV: must be 16 bytes (32 hex characters).
    
    Args:
        iv_hex: Hexadecimal string representing the IV
        
    Returns:
        bool: True if valid AES IV
    """
    if not iv_hex or not isinstance(iv_hex, str):
        return False
    if len(iv_hex) != 32:
        return False
    try:
        bytes.fromhex(iv_hex)
        return True
    except ValueError:
        return False


def validate_ed25519_public_key(public_key_pem):
    """
    Validate Ed25519 public key in PEM format.
    
    Args:
        public_key_pem: PEM-encoded public key string
        
    Returns:
        bool: True if valid Ed25519 public key
    """
    if not public_key_pem or not isinstance(public_key_pem, str):
        return False
    
    try:
        key = ECC.import_key(public_key_pem)
        return key.curve == 'Ed25519'
    except (ValueError, Exception):
        return False


def validate_aes_encrypted_data(encrypted_data_base64):
    """
    Validate AES encrypted data format (base64).
    
    Args:
        encrypted_data_base64: Base64-encoded encrypted data
        
    Returns:
        bool: True if valid base64 AES encrypted data
    """
    if not encrypted_data_base64 or not isinstance(encrypted_data_base64, str):
        return False
    
    try:
        decoded = base64.b64decode(encrypted_data_base64)
        # AES encrypted data should be at least 16 bytes (one block)
        return len(decoded) >= 16
    except Exception:
        return False


def validate_registration_data(data):
    """
    Validate all registration data fields.
    
    Args:
        data: Dictionary containing registration data
        
    Returns:
        tuple: (is_valid, error_message)
    """
    # Check required fields
    required_fields = ['username', 'email', 'password_hash', 'encrypted_private_key', 
                       'public_key', 'encryption_iv', 'signature']
    
    if not data:
        return False, 'No data provided'
    
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return False, f'Missing required fields: {", ".join(missing_fields)}'
    
    # Validate email
    if not validate_email(data['email']):
        return False, 'Invalid email format'
    
    # Validate username
    if not validate_username(data['username']):
        return False, 'Invalid username: must be max 24 characters, alphanumeric with _ or - only'
    
    # Validate Argon2ID password hash
    if not validate_argon2_hash(data['password_hash']):
        return False, 'Invalid password hash: must be Argon2ID format'
    
    # Validate AES IV
    if not validate_aes_iv(data['encryption_iv']):
        return False, 'Invalid encryption IV: must be 32 hex characters (16 bytes)'
    
    # Validate Ed25519 public key
    if not validate_ed25519_public_key(data['public_key']):
        return False, 'Invalid public key: must be Ed25519 format'
    
    # Validate encrypted private key
    if not validate_aes_encrypted_data(data['encrypted_private_key']):
        return False, 'Invalid encrypted private key: must be valid base64 AES encrypted data'
    
    return True, None
