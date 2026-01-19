"""Authentication utilities for signature verification and timestamp validation."""

import json
import time
from functools import wraps
from flask import request, jsonify, session, current_app
from app import db
from app.models import User
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


def validate_timestamp(timestamp, max_age_seconds=300):
    """
    Validate timestamp is recent to prevent replay attacks.
    
    Args:
        timestamp: Unix timestamp in seconds
        max_age_seconds: Maximum age of request in seconds (default 5 minutes)
        
    Returns:
        bool: True if timestamp is valid
    """
    try:
        timestamp = int(timestamp)
        current_time = int(time.time())
        
        # Check if timestamp is not too old
        if current_time - timestamp > max_age_seconds:
            return False
        
        # Check if timestamp is not in the future (allow 30 seconds clock drift)
        if timestamp - current_time > 30:
            return False
        
        return True
    except (ValueError, TypeError):
        return False


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
        # Get request data - check header for GET requests, body for POST
        if request.method == 'GET':
            signature_header = request.headers.get('X-Signature-Data')
            if not signature_header:
                return jsonify({'error': 'No signature data provided'}), 400
            try:
                request_body = json.loads(signature_header)
            except json.JSONDecodeError:
                return jsonify({'error': 'Invalid signature data format'}), 400
        else:
            request_body = request.get_json()
            if not request_body:
                return jsonify({'error': 'No data provided'}), 400
        
        # Check required fields
        if 'signature' not in request_body:
            return jsonify({'error': 'Signature is required'}), 400
        
        if 'timestamp' not in request_body:
            return jsonify({'error': 'Timestamp is required'}), 400
        
        if 'data' not in request_body:
            return jsonify({'error': 'Data field is required'}), 400
        
        # Validate timestamp
        if not validate_timestamp(request_body['timestamp']):
            return jsonify({'error': 'Invalid or expired timestamp'}), 401
        
        # Get user from session
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return jsonify({'error': 'User not found'}), 404
        
        # Verify signature
        data_to_verify = {
            'data': request_body['data'],
            'timestamp': request_body['timestamp']
        }
        
        if not verify_signature(user.public_key, data_to_verify, request_body['signature']):
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Replace request data with the inner data for the route handler
        request.signed_data = request_body['data']
        request.verified_timestamp = request_body['timestamp']
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_signature_with_identifier(f):
    """
    Decorator for routes that don't have a session yet (like login).
    Requires email or username in the data to look up the public key.
    
    Expected request format:
    {
        "data": {
            "email": "..." OR "username": "...",
            ... other data ...
        },
        "signature": "hex_signature",
        "timestamp": 1234567890
    }
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get request data
        request_body = request.get_json()
        
        if not request_body:
            return jsonify({'error': 'No data provided'}), 400
        
        # Check required fields
        if 'signature' not in request_body:
            return jsonify({'error': 'Signature is required'}), 400
        
        if 'timestamp' not in request_body:
            return jsonify({'error': 'Timestamp is required'}), 400
        
        if 'data' not in request_body:
            return jsonify({'error': 'Data field is required'}), 400
        
        # Check for email or username
        email = request_body['data'].get('email')
        username = request_body['data'].get('username')
        
        if not email and not username:
            return jsonify({'error': 'Email or username is required in data'}), 400
        
        # Validate timestamp
        if not validate_timestamp(request_body['timestamp']):
            return jsonify({'error': 'Invalid or expired timestamp'}), 401
        
        # Get user by email or username
        if email:
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'error': 'Invalid email'}), 401
        else:
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({'error': 'Invalid username'}), 401
        
        # Verify signature
        data_to_verify = {
            'data': request_body['data'],
            'timestamp': request_body['timestamp']
        }
        
        if not verify_signature(user.public_key, data_to_verify, request_body['signature']):
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Replace request data with the inner data for the route handler
        request.signed_data = request_body['data']
        request.verified_timestamp = request_body['timestamp']
        request.verified_user = user
        
        return f(*args, **kwargs)
    
    return decorated_function


# Backward compatibility alias
require_signature_with_username = require_signature_with_identifier
