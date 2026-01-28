"""Authentication routes for user registration and login."""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import User
from app.validators import validate_registration_data
from app.auth_utils import require_signature, verify_signature
from app.constants import (
    MAX_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW, SIGNATURE_MAX_AGE,
    ERROR_EMAIL_REQUIRED, ERROR_USER_NOT_FOUND, ERROR_NO_DATA_PROVIDED,
    ERROR_SIGNATURE_REQUIRED, ERROR_TIMESTAMP_EXPIRED, ERROR_INVALID_TIMESTAMP,
    ERROR_DUPLICATE_USERNAME, ERROR_DUPLICATE_EMAIL, ERROR_INVALID_SIGNATURE,
    ERROR_NO_PENDING_REGISTRATION, ERROR_TOTP_REQUIRED, ERROR_INVALID_2FA,
    ERROR_NOT_AUTHENTICATED, ERROR_INVALID_CREDENTIALS, ERROR_EMAIL_OR_USERNAME_REQUIRED,
    ERROR_PASSWORD_AND_TOTP_REQUIRED, ERROR_PASSWORD_AND_RECOVERY_REQUIRED,
    ERROR_NO_2FA_RESET_REQUIRED, ERROR_NO_PENDING_2FA_RESET
)
from app.errors import (
    error_response, unauthorized_response, not_found_response, 
    validation_error_response, conflict_response
)
import json
import time
import pyotp
import qrcode
import io
import base64

auth_bp = Blueprint('auth', __name__, url_prefix='/api')

# Rate limiting: Track failed login attempts by (IP, email) combination
# Structure: {(ip, email): {'count': int, 'blocked_until': timestamp}}
login_attempts = {}

def check_rate_limit(ip_address, identifier):
    """Check if IP-identifier combination is rate limited."""
    key = (ip_address, identifier.lower())
    current_time = time.time()
    
    if key in login_attempts:
        attempt_data = login_attempts[key]
        
        # Check if currently blocked
        if 'blocked_until' in attempt_data and attempt_data['blocked_until'] > current_time:
            return False, "Too many failed attempts. Please try again later."
        
        # If block expired, reset
        if 'blocked_until' in attempt_data and attempt_data['blocked_until'] <= current_time:
            del login_attempts[key]
    
    return True, None

def record_failed_attempt(ip_address, identifier):
    """Record a failed login attempt."""
    key = (ip_address, identifier.lower())
    current_time = time.time()
    
    if key not in login_attempts:
        login_attempts[key] = {'count': 1}
    else:
        login_attempts[key]['count'] += 1
    
    # If reached max attempts, block for 5 minutes
    if login_attempts[key]['count'] >= MAX_LOGIN_ATTEMPTS:
        login_attempts[key]['blocked_until'] = current_time + RATE_LIMIT_WINDOW

def clear_failed_attempts(ip_address, identifier):
    """Clear failed attempts on successful login."""
    key = (ip_address, identifier.lower())
    if key in login_attempts:
        del login_attempts[key]


@auth_bp.route('/get-encrypted-key', methods=['POST'])
def get_encrypted_key():
    """Get encrypted private key for a user by email (no authentication required)."""
    data = request.get_json()
    
    if not data or not data.get('email'):
        return validation_error_response(ERROR_EMAIL_REQUIRED)
    
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return not_found_response(ERROR_USER_NOT_FOUND)
    
    return jsonify({
        'encrypted_private_key': user.encrypted_private_key,
        'encryption_iv': user.encryption_iv
    }), 200


@auth_bp.route('/register', methods=['POST'])
def register():
    request_body = request.get_json()
    
    if not request_body:
        return validation_error_response(ERROR_NO_DATA_PROVIDED)
    
    # Check for required signature fields
    if 'signature' not in request_body or 'timestamp' not in request_body or 'data' not in request_body:
        return validation_error_response(ERROR_SIGNATURE_REQUIRED)
    
    # Validate timestamp (5 minute window)
    try:
        timestamp = int(request_body['timestamp'])
        current_time = int(time.time())
        if abs(current_time - timestamp) > SIGNATURE_MAX_AGE:
            return unauthorized_response(ERROR_TIMESTAMP_EXPIRED)
    except (ValueError, TypeError):
        return validation_error_response(ERROR_INVALID_TIMESTAMP)
    
    data = request_body['data']
    
    # Validate all fields
    is_valid, error_message = validate_registration_data(data)
    if not is_valid:
        return validation_error_response(error_message)
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return conflict_response(ERROR_DUPLICATE_USERNAME)
    
    if User.query.filter_by(email=data['email']).first():
        return conflict_response(ERROR_DUPLICATE_EMAIL)
    
    # Verify Ed25519 signature
    data_to_verify = {
        'data': data,
        'timestamp': request_body['timestamp']
    }
    
    if not verify_signature(data['public_key'], data_to_verify, request_body['signature']):
        return validation_error_response(ERROR_INVALID_SIGNATURE)
    
    # Generate 2FA secret using pyotp
    twofa_secret = pyotp.random_base32()
    
    # Generate recovery codes (10 codes, 24 characters each)
    import secrets
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    recovery_codes = []
    hashed_recovery_codes = []
    for _ in range(10):
        charset = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*_=+-~?'
        code = '-'.join([''.join(secrets.choice(charset) for _ in range(4)) for _ in range(6)])
        recovery_codes.append(code)
        # Hash the recovery code using Argon2id before storing
        hashed_code = ph.hash(code)
        hashed_recovery_codes.append(hashed_code)
    
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
    img.save(buffer)
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
        'twofa_secret': twofa_secret,
        'recovery_codes': hashed_recovery_codes
    }
    session.modified = True  # Explicitly mark session as modified
    
    return jsonify({
        'message': 'Please verify your 2FA code to complete registration',
        'qr_code': f'data:image/png;base64,{qr_code_base64}',
        'secret': twofa_secret,
        'provisioning_uri': provisioning_uri,
        'recovery_codes': recovery_codes
    }), 200


@auth_bp.route('/register/verify-2fa', methods=['POST'])
def verify_2fa():
    """Verify 2FA code and complete registration."""
    request_body = request.get_json()
    
    if not request_body:
        return validation_error_response(ERROR_NO_DATA_PROVIDED)
    
    # Check for required signature fields
    if 'signature' not in request_body or 'timestamp' not in request_body or 'data' not in request_body:
        return validation_error_response(ERROR_SIGNATURE_REQUIRED)
    
    # Check if there's a pending user
    if 'pending_user' not in session:
        return validation_error_response(ERROR_NO_PENDING_REGISTRATION)
    
    # Validate timestamp
    try:
        timestamp = int(request_body['timestamp'])
        current_time = int(time.time())
        if abs(current_time - timestamp) > SIGNATURE_MAX_AGE:
            return unauthorized_response(ERROR_TIMESTAMP_EXPIRED)
    except (ValueError, TypeError):
        return validation_error_response(ERROR_INVALID_TIMESTAMP)
    
    data = request_body['data']
    
    # Validate TOTP code
    if not data or not data.get('totp_code'):
        return validation_error_response(ERROR_TOTP_REQUIRED)
    
    # Verify signature using pending user's public key
    pending_user = session['pending_user']
    data_to_verify = {
        'data': data,
        'timestamp': request_body['timestamp']
    }
    
    if not verify_signature(pending_user['public_key'], data_to_verify, request_body['signature']):
        return unauthorized_response(ERROR_INVALID_SIGNATURE)
    
    totp = pyotp.TOTP(pending_user['twofa_secret'])
    
    # Verify the code (with window for time drift)
    if not totp.verify(data['totp_code'], valid_window=1):
        return unauthorized_response(ERROR_INVALID_2FA)
    
    # Create the user now that 2FA is verified
    import json
    from sqlalchemy.exc import IntegrityError
    
    # Double-check username and email don't exist (prevent race condition)
    if User.query.filter_by(username=pending_user['username']).first():
        session.pop('pending_user', None)
        return conflict_response(ERROR_DUPLICATE_USERNAME)
    
    if User.query.filter_by(email=pending_user['email']).first():
        session.pop('pending_user', None)
        return conflict_response(ERROR_DUPLICATE_EMAIL)
    
    user = User(
        username=pending_user['username'],
        email=pending_user['email'],
        password_hash=pending_user['password_hash'],
        encrypted_private_key=pending_user['encrypted_private_key'],
        public_key=pending_user['public_key'],
        encryption_iv=pending_user['encryption_iv'],
        twofa_secret=pending_user['twofa_secret'],
        recovery_codes=json.dumps(pending_user.get('recovery_codes', []))
    )
    
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        session.pop('pending_user', None)
        return conflict_response(ERROR_DUPLICATE_USERNAME)
    
    # Clear pending user from session
    session.pop('pending_user', None)
    
    # Create session for the user
    session['user_id'] = user.id
    session['username'] = user.username
    
    # Notify all connected users about new user
    from app.socket_events import emit_user_registered
    emit_user_registered({
        'id': user.id,
        'username': user.username,
        'public_key': user.public_key
    })
    
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
    # Start timing to prevent timing attacks
    import random
    start_time = time.time()
    min_response_time = 1.0  # Minimum 1 second response time
    
    data = request.get_json()
    
    if not data:
        # Add delay before returning error
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return validation_error_response(ERROR_NO_DATA_PROVIDED)
    
    # Check for email or username
    email = data.get('email')
    username = data.get('username')
    
    # Get IP address for rate limiting
    ip_address = request.remote_addr
    identifier = email if email else username
    
    # Check rate limit
    if identifier:
        allowed, error_msg = check_rate_limit(ip_address, identifier)
        if not allowed:
            elapsed = time.time() - start_time
            if elapsed < min_response_time:
                time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
            return error_response(error_msg, 429)
    
    if not email and not username:
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return validation_error_response(ERROR_EMAIL_OR_USERNAME_REQUIRED)
    
    # Validate required fields
    if not data.get('password_hash') or not data.get('totp_code'):
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return validation_error_response(ERROR_PASSWORD_AND_TOTP_REQUIRED)
    
    # Get user by email or username
    if email:
        user = User.query.filter_by(email=email).first()
        if not user:
            record_failed_attempt(ip_address, identifier)
            elapsed = time.time() - start_time
            if elapsed < min_response_time:
                time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
            return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    else:
        user = User.query.filter_by(username=username).first()
        if not user:
            record_failed_attempt(ip_address, identifier)
            elapsed = time.time() - start_time
            if elapsed < min_response_time:
                time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
            return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Compare password hashes directly
    if user.password_hash != data['password_hash']:
        record_failed_attempt(ip_address, identifier)
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Verify 2FA code
    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(data['totp_code'], valid_window=1):
        record_failed_attempt(ip_address, identifier)
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Clear failed attempts on successful login
    clear_failed_attempts(ip_address, identifier)
    
    # Check if user is already logged in from another session
    from app import session_manager
    from app.socket_events import emit_force_logout
    
    if session_manager.has_sessions(user.id):
        old_session_ids = session_manager.get_sessions(user.id)
        # Emit force logout to all old sessions
        emit_force_logout(old_session_ids)
        # Clear old sessions (new sessions will be added when WebSocket connects)
        session_manager.clear_user_sessions(user.id)
    
    # Create session for the user
    session['user_id'] = user.id
    session['username'] = user.username
    
    # Ensure minimum response time even for successful login
    elapsed = time.time() - start_time
    if elapsed < min_response_time:
        time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'encrypted_private_key': user.encrypted_private_key,
            'encryption_iv': user.encryption_iv,
            'public_key': user.public_key,
            'requires_2fa_reset': user.requires_2fa_reset
        }
    }), 200


@auth_bp.route('/login/recovery', methods=['POST'])
def login_with_recovery():
    """Login with recovery code when user lost access to authenticator app."""
    # Start timing to prevent timing attacks
    import random
    start_time = time.time()
    min_response_time = 1.0  # Minimum 1 second response time
    
    data = request.get_json()
    
    if not data:
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return validation_error_response(ERROR_NO_DATA_PROVIDED)
    
    # Check for email or username
    email = data.get('email')
    username = data.get('username')
    
    # Get IP address for rate limiting
    ip_address = request.remote_addr
    identifier = email if email else username
    
    # Check rate limit
    if identifier:
        allowed, error_msg = check_rate_limit(ip_address, identifier)
        if not allowed:
            elapsed = time.time() - start_time
            if elapsed < min_response_time:
                time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
            return error_response(error_msg, 429)
    
    if not email and not username:
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return validation_error_response(ERROR_EMAIL_OR_USERNAME_REQUIRED)
    
    # Validate required fields
    if not data.get('password_hash') or not data.get('recovery_code'):
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return validation_error_response(ERROR_PASSWORD_AND_RECOVERY_REQUIRED)
    
    # Get user by email or username
    if email:
        user = User.query.filter_by(email=email).first()
        if not user:
            record_failed_attempt(ip_address, identifier)
            elapsed = time.time() - start_time
            if elapsed < min_response_time:
                time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
            return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    else:
        user = User.query.filter_by(username=username).first()
        if not user:
            record_failed_attempt(ip_address, identifier)
            elapsed = time.time() - start_time
            if elapsed < min_response_time:
                time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
            return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Compare password hashes directly
    if user.password_hash != data['password_hash']:
        record_failed_attempt(ip_address, identifier)
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Verify recovery code
    if not user.recovery_codes:
        record_failed_attempt(ip_address, identifier)
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Load and verify recovery codes
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ph = PasswordHasher()
    stored_codes = json.loads(user.recovery_codes)
    
    # Try to verify the provided code against stored hashes
    code_valid = False
    code_index = -1
    for idx, hashed_code in enumerate(stored_codes):
        try:
            ph.verify(hashed_code, data['recovery_code'])
            code_valid = True
            code_index = idx
            break
        except (VerifyMismatchError, Exception):
            continue
    
    if not code_valid:
        record_failed_attempt(ip_address, identifier)
        elapsed = time.time() - start_time
        if elapsed < min_response_time:
            time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
        return unauthorized_response(ERROR_INVALID_CREDENTIALS)
    
    # Clear failed attempts on successful recovery login
    clear_failed_attempts(ip_address, identifier)
    
    # Mark this code as used by removing it
    stored_codes.pop(code_index)
    user.recovery_codes = json.dumps(stored_codes)
    # Set flag to require 2FA reset
    user.requires_2fa_reset = True
    db.session.commit()
    
    # Create session for the user
    session['user_id'] = user.id
    session['username'] = user.username
    
    # Ensure minimum response time
    elapsed = time.time() - start_time
    if elapsed < min_response_time:
        time.sleep(min_response_time - elapsed + random.uniform(0, 0.2))
    
    return jsonify({
        'message': 'Login successful with recovery code',
        'warning': 'You used a recovery code. You must set up 2FA again immediately.',
        'recovery_codes_remaining': len(stored_codes),
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'encrypted_private_key': user.encrypted_private_key,
            'encryption_iv': user.encryption_iv,
            'public_key': user.public_key,
            'requires_2fa_reset': True
        }
    }), 200


@auth_bp.route('/reset-2fa', methods=['POST'])
def reset_2fa():
    """Initiate 2FA reset for users who logged in with recovery code."""
    # Check if user is logged in
    if 'user_id' not in session:
        return unauthorized_response(ERROR_NOT_AUTHENTICATED)
    
    user = User.query.get(session['user_id'])
    if not user:
        return not_found_response(ERROR_USER_NOT_FOUND)
    
    # Check if user needs to reset 2FA
    if not user.requires_2fa_reset:
        return validation_error_response(ERROR_NO_2FA_RESET_REQUIRED)
    
    # Generate new 2FA secret
    twofa_secret = pyotp.random_base32()
    
    # Generate new recovery codes (10 codes, 24 characters each)
    import secrets
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    recovery_codes = []
    hashed_recovery_codes = []
    for _ in range(10):
        charset = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*_=+-~?'
        code = '-'.join([''.join(secrets.choice(charset) for _ in range(4)) for _ in range(6)])
        recovery_codes.append(code)
        hashed_code = ph.hash(code)
        hashed_recovery_codes.append(hashed_code)
    
    # Create TOTP provisioning URI
    totp = pyotp.TOTP(twofa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='Secure Chat App'
    )
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Store pending reset data in session
    session['pending_2fa_reset'] = {
        'twofa_secret': twofa_secret,
        'recovery_codes': hashed_recovery_codes
    }
    session.modified = True
    
    return jsonify({
        'message': 'Scan the QR code and verify with your authenticator app',
        'qr_code': f'data:image/png;base64,{qr_code_base64}',
        'secret': twofa_secret,
        'provisioning_uri': provisioning_uri,
        'recovery_codes': recovery_codes
    }), 200


@auth_bp.route('/reset-2fa/verify', methods=['POST'])
def verify_2fa_reset():
    """Verify and complete 2FA reset."""
    # Check if user is logged in
    if 'user_id' not in session:
        return unauthorized_response(ERROR_NOT_AUTHENTICATED)
    
    # Check if there's a pending reset
    if 'pending_2fa_reset' not in session:
        return validation_error_response(ERROR_NO_PENDING_2FA_RESET)
    
    data = request.get_json()
    if not data or not data.get('totp_code'):
        return validation_error_response(ERROR_TOTP_REQUIRED)
    
    user = User.query.get(session['user_id'])
    if not user:
        return not_found_response(ERROR_USER_NOT_FOUND)
    
    pending_reset = session['pending_2fa_reset']
    totp = pyotp.TOTP(pending_reset['twofa_secret'])
    
    # Verify the code (with window for time drift)
    if not totp.verify(data['totp_code'], valid_window=1):
        return unauthorized_response(ERROR_INVALID_2FA)
    
    # Update user's 2FA settings
    user.twofa_secret = pending_reset['twofa_secret']
    user.recovery_codes = json.dumps(pending_reset['recovery_codes'])
    user.requires_2fa_reset = False
    db.session.commit()
    
    # Clear pending reset from session
    session.pop('pending_2fa_reset', None)
    
    return jsonify({
        'message': '2FA reset successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'requires_2fa_reset': False
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
