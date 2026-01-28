"""Authentication utilities for signature verification and timestamp validation."""

import json
from functools import wraps
from flask import request, session
from app.models import User
from app.helpers import is_valid_timestamp as helper_is_valid_timestamp
from app.constants import (
    SIGNATURE_MAX_AGE,
    ERROR_NO_SIGNATURE_DATA, ERROR_INVALID_SIGNATURE_FORMAT, ERROR_NO_DATA_PROVIDED,
    ERROR_SIGNATURE_REQUIRED, ERROR_TIMESTAMP_EXPIRED, ERROR_DATA_FIELD_REQUIRED,
    ERROR_NOT_AUTHENTICATED, ERROR_USER_NOT_FOUND, ERROR_INVALID_SIGNATURE
)
from app.errors import (
    validation_error_response, unauthorized_response, not_found_response
)
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA256


def verify_signature(public_key_pem, data, signature_hex):
    """
    Verify Ed25519 signature.
    
    Args:
        public_key_pem: PEM-encoded Ed25519 public key
        data: Dictionary of data that was signed
        signature_hex: Hex-encoded signature
        
    Returns:
        bool: True if signature is valid
    """
    try:
        # Create hash of the data
        # IMPORTANT: Do NOT sort_keys - must match frontend JSON.stringify() order
        data_string = json.dumps(data, separators=(',', ':'))
        data_hash = SHA256.new(data_string.encode()).digest()
        
        # Load Ed25519 public key
        public_key_obj = ECC.import_key(public_key_pem)
        
        # Verify signature
        signature_bytes = bytes.fromhex(signature_hex)
        verifier = eddsa.new(public_key_obj, 'rfc8032')
        verifier.verify(data_hash, signature_bytes)
        return True
    except Exception:
        return False


def validate_timestamp(timestamp, max_age_seconds=SIGNATURE_MAX_AGE):
    """
    Validate timestamp is recent to prevent replay attacks.
    
    Args:
        timestamp: Unix timestamp in seconds
        max_age_seconds: Maximum age of request in seconds (default from SIGNATURE_MAX_AGE constant)
        
    Returns:
        bool: True if timestamp is valid
    """
    # Use the helper function from helpers.py
    return helper_is_valid_timestamp(timestamp, max_age_seconds)


def require_signature(f):
    """
    Decorator to require signature verification for protected routes.
    
    For POST requests, expected body format:
    {
        "data": { ... actual request data ... },
        "signature": "hex_signature",
        "timestamp": 1234567890
    }
    
    For GET requests, signature data is in X-Signature-Data header.
    
    The signature is computed over: {"data": {...}, "timestamp": ...}
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get request data - check header for GET/DELETE requests, body for POST/PUT
        if request.method in ['GET', 'DELETE']:
            signature_header = request.headers.get('X-Signature-Data')
            if not signature_header:
                return validation_error_response(ERROR_NO_SIGNATURE_DATA)
            try:
                request_body = json.loads(signature_header)
            except json.JSONDecodeError:
                return validation_error_response(ERROR_INVALID_SIGNATURE_FORMAT)
        else:
            request_body = request.get_json()
            if not request_body:
                return validation_error_response(ERROR_NO_DATA_PROVIDED)
        
        # Check required fields
        if 'signature' not in request_body:
            return validation_error_response(ERROR_SIGNATURE_REQUIRED)
        
        if 'timestamp' not in request_body:
            return validation_error_response(ERROR_SIGNATURE_REQUIRED)
        
        if 'data' not in request_body:
            return validation_error_response(ERROR_DATA_FIELD_REQUIRED)
        
        # Validate timestamp
        if not validate_timestamp(request_body['timestamp']):
            return unauthorized_response(ERROR_TIMESTAMP_EXPIRED)
        
        # Get user from session
        if 'user_id' not in session:
            return unauthorized_response(ERROR_NOT_AUTHENTICATED)
        
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return not_found_response(ERROR_USER_NOT_FOUND)
        
        # Verify signature
        data_to_verify = {
            'data': request_body['data'],
            'timestamp': request_body['timestamp']
        }
        
        if not verify_signature(user.public_key, data_to_verify, request_body['signature']):
            return unauthorized_response(ERROR_INVALID_SIGNATURE)
        
        # Replace request data with the inner data for the route handler
        request.signed_data = request_body['data']
        request.verified_timestamp = request_body['timestamp']
        
        return f(*args, **kwargs)
    
    return decorated_function
