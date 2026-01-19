"""Authentication routes for user registration and login."""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import User
from app.validators import validate_registration_data
from app.auth_utils import require_signature, verify_signature
import json
import time
import pyotp
import qrcode
import io
import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA256

auth_bp = Blueprint('auth', __name__, url_prefix='/api')


@auth_bp.route('/get-encrypted-key', methods=['POST'])
def get_encrypted_key():
    """Get encrypted private key for a user by email (no authentication required)."""
    data = request.get_json()
    
    if not data or not data.get('email'):
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'encrypted_private_key': user.encrypted_private_key,
        'encryption_iv': user.encryption_iv
    }), 200


@auth_bp.route('/register', methods=['POST'])
def register():
    request_body = request.get_json()
    
    if not request_body:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check for required signature fields
    if 'signature' not in request_body or 'timestamp' not in request_body or 'data' not in request_body:
        return jsonify({'error': 'Signature, timestamp, and data are required'}), 400
    
    # Validate timestamp (5 minute window)
    try:
        timestamp = int(request_body['timestamp'])
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:
            return jsonify({'error': 'Invalid or expired timestamp'}), 401
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid timestamp format'}), 400
    
    data = request_body['data']
    
    # Validate all fields
    is_valid, error_message = validate_registration_data(data)
    if not is_valid:
        return jsonify({'error': error_message}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Verify Ed25519 signature
    # For registration, the frontend signs {data: {...}, timestamp: ...}
    # We need to verify against the exact structure that was signed
    data_to_verify = {
        'data': data,
        'timestamp': request_body['timestamp']
    }
    
    if not verify_signature(data['public_key'], data_to_verify, request_body['signature']):
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Generate 2FA secret using pyotp
    twofa_secret = pyotp.random_base32()
    
    # Create TOTP provisioning URI
    totp = pyotp.TOTP(twofa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=data['email'],
        issuer_name='Secure Chat App'
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffer = io.BytesIO()
    img.save(buffer)  # PyPNGImage doesn't accept format argument
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Store user data temporarily in session for verification
    session['pending_user'] = {
        'username': data['username'],
        'email': data['email'],
        'password_hash': data['password_hash'],
        'encrypted_private_key': data['encrypted_private_key'],
        'public_key': data['public_key'],
        'encryption_iv': data['encryption_iv'],
        'twofa_secret': twofa_secret
    }
    session.modified = True  # Explicitly mark session as modified
    
    print(f"[DEBUG] Session created for {data['username']}, session ID: {session.get('_id', 'no-id')}")
    print(f"[DEBUG] Pending user stored: {session.get('pending_user', {}).get('username', 'none')}")
    
    return jsonify({
        'message': 'Please verify your 2FA code to complete registration',
        'qr_code': f'data:image/png;base64,{qr_code_base64}',
        'secret': twofa_secret,
        'provisioning_uri': provisioning_uri
    }), 200


@auth_bp.route('/register/verify-2fa', methods=['POST'])
def verify_2fa():
    """Verify 2FA code and complete registration."""
    request_body = request.get_json()
    
    if not request_body:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check for required signature fields
    if 'signature' not in request_body or 'timestamp' not in request_body or 'data' not in request_body:
        return jsonify({'error': 'Signature, timestamp, and data are required'}), 400
    
    # Check if there's a pending user
    print(f"[DEBUG] Verify 2FA - Session keys: {list(session.keys())}")
    print(f"[DEBUG] Verify 2FA - Has pending_user: {'pending_user' in session}")
    
    if 'pending_user' not in session:
        return jsonify({'error': 'No pending registration found'}), 400
    
    # Validate timestamp
    try:
        timestamp = int(request_body['timestamp'])
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:
            return jsonify({'error': 'Invalid or expired timestamp'}), 401
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid timestamp format'}), 400
    
    data = request_body['data']
    
    # Validate TOTP code
    if not data or not data.get('totp_code'):
        return jsonify({'error': 'TOTP code is required'}), 400
    
    # Verify signature using pending user's public key
    pending_user = session['pending_user']
    data_to_verify = {
        'data': data,
        'timestamp': request_body['timestamp']
    }
    
    if not verify_signature(pending_user['public_key'], data_to_verify, request_body['signature']):
        return jsonify({'error': 'Invalid signature'}), 401
    
    totp = pyotp.TOTP(pending_user['twofa_secret'])
    
    # Verify the code (with window for time drift)
    if not totp.verify(data['totp_code'], valid_window=1):
        return jsonify({'error': 'Invalid 2FA code'}), 401
    
    # Create the user now that 2FA is verified
    user = User(
        username=pending_user['username'],
        email=pending_user['email'],
        password_hash=pending_user['password_hash'],
        encrypted_private_key=pending_user['encrypted_private_key'],
        public_key=pending_user['public_key'],
        encryption_iv=pending_user['encryption_iv'],
        twofa_secret=pending_user['twofa_secret']
    )
    db.session.add(user)
    db.session.commit()
    
    # Clear pending user from session
    session.pop('pending_user', None)
    
    # Create session for the user
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'public_key': user.public_key
        }
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """Login a user with email, password hash and 2FA code."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check for email or username
    email = data.get('email')
    username = data.get('username')
    
    if not email and not username:
        return jsonify({'error': 'Email or username is required'}), 400
    
    # Validate required fields
    if not data.get('password_hash') or not data.get('totp_code'):
        return jsonify({'error': 'Password_hash and totp_code are required'}), 400
    
    # Get user by email or username
    if email:
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
    else:
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401
    
    # Compare password hashes directly
    if user.password_hash != data['password_hash']:
        return jsonify({'error': 'Invalid password'}), 401
    
    # Verify 2FA code
    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(data['totp_code'], valid_window=1):
        return jsonify({'error': 'Invalid 2FA code'}), 401
    
    # Create session for the user
    session['user_id'] = user.id
    session['username'] = user.username
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'encrypted_private_key': user.encrypted_private_key,
            'encryption_iv': user.encryption_iv,
            'public_key': user.public_key
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@require_signature
def logout():
    """Logout the current user."""
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200


@auth_bp.route('/me', methods=['POST'])
@require_signature
def me():
    """Get current logged-in user."""
    # User already verified by decorator
    user = User.query.get(session['user_id'])
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat(),
        'public_key': user.public_key,
        'encrypted_private_key': user.encrypted_private_key,
        'encryption_iv': user.encryption_iv
    }), 200
