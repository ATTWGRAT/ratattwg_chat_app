"""Authentication routes for user registration and login."""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import User
from app.validators import validate_registration_data
import json
import secrets
import pyotp
import qrcode
import io
import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA256

auth_bp = Blueprint('auth', __name__, url_prefix='/api')


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user with zero-knowledge security."""
    data = request.get_json()
    
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
    try:
        # Reconstruct data to verify (fields a-e)
        data_to_verify = {
            'email': data['email'],
            'username': data['username'],
            'password_hash': data['password_hash'],
            'encrypted_private_key': data['encrypted_private_key'],
            'public_key': data['public_key'],
            'encryption_iv': data['encryption_iv']
        }
        
        # Create hash of the data
        data_string = json.dumps(data_to_verify, sort_keys=True)
        data_hash = SHA256.new(data_string.encode()).digest()
        
        # Load Ed25519 public key
        public_key_obj = ECC.import_key(data['public_key'])
        
        # Verify signature
        signature_bytes = bytes.fromhex(data['signature'])
        verifier = eddsa.new(public_key_obj, 'rfc8032')
        verifier.verify(data_hash, signature_bytes)
        
    except (ValueError, TypeError, Exception) as e:
        return jsonify({'error': f'Invalid signature: {str(e)}'}), 400
    
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
    img.save(buffer, format='PNG')
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
    
    return jsonify({
        'message': 'Please verify your 2FA code to complete registration',
        'qr_code': f'data:image/png;base64,{qr_code_base64}',
        'secret': twofa_secret,
        'provisioning_uri': provisioning_uri
    }), 200


@auth_bp.route('/register/verify-2fa', methods=['POST'])
def verify_2fa():
    """Verify 2FA code and complete registration."""
    data = request.get_json()
    
    # Check if there's a pending user
    if 'pending_user' not in session:
        return jsonify({'error': 'No pending registration found'}), 400
    
    # Validate TOTP code
    if not data or not data.get('totp_code'):
        return jsonify({'error': 'TOTP code is required'}), 400
    
    pending_user = session['pending_user']
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
    """Login a user with password hash and 2FA code."""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('username') or not data.get('password_hash') or not data.get('totp_code'):
        return jsonify({'error': 'Username, password_hash, and totp_code are required'}), 400
    
    # Find user
    user = User.query.filter_by(username=data['username']).first()
    
    # Compare password hashes directly
    if not user or user.password_hash != data['password_hash']:
        return jsonify({'error': 'Invalid username or password'}), 401
    
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
def logout():
    """Logout the current user."""
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200


@auth_bp.route('/me', methods=['GET'])
def me():
    """Get current logged-in user."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat(),
        'public_key': user.public_key,
        'encrypted_private_key': user.encrypted_private_key,
        'encryption_iv': user.encryption_iv
    }), 200
