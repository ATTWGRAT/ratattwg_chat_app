# Message Signature Protocol

## Overview

All requests to the server (except registration) **must** include:
1. **Signature** - Ed25519 signature of the request
2. **Timestamp** - Unix timestamp to prevent replay attacks
3. **Data** - The actual request payload

This ensures that:
- ✅ Only the key owner can make requests
- ✅ Requests cannot be replayed (timestamp validation)
- ✅ Request integrity is verified (signature)
- ✅ Server validates against user's stored public key

## Request Format

### Standard Format (All Endpoints)

```json
{
  "data": {
    "field1": "value1",
    "field2": "value2"
  },
  "signature": "hex_encoded_ed25519_signature",
  "timestamp": 1737302400
}
```

### What Gets Signed

The signature is computed over:
```json
{
  "data": { ... },
  "timestamp": 1737302400
}
```

**Important:** Sign the entire object containing both `data` and `timestamp`, not just the data field.

## Client-Side Implementation

### 1. Creating a Signed Request

```javascript
import { ed25519 } from '@noble/curves/ed25519';

async function createSignedRequest(data, privateKey) {
  // 1. Generate current timestamp
  const timestamp = Math.floor(Date.now() / 1000);
  
  // 2. Create object to sign
  const toSign = {
    data: data,
    timestamp: timestamp
  };
  
  // 3. Hash the data
  const encoder = new TextEncoder();
  const dataString = JSON.stringify(toSign);
  const dataHash = await crypto.subtle.digest('SHA-256', encoder.encode(dataString));
  
  // 4. Sign with Ed25519 private key
  const signature = ed25519.sign(new Uint8Array(dataHash), privateKey);
  
  // 5. Convert signature to hex
  const signatureHex = Array.from(signature)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  // 6. Return complete request
  return {
    data: data,
    signature: signatureHex,
    timestamp: timestamp
  };
}
```

### 2. Example Usage

#### Login Request
```javascript
const loginData = {
  username: 'john_doe',
  password_hash: '4f8a9b2e...',
  totp_code: '123456'
};

const signedRequest = await createSignedRequest(loginData, privateKeyBytes);

await fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(signedRequest)
});
```

#### Logout Request
```javascript
const logoutData = {};  // Empty data for logout

const signedRequest = await createSignedRequest(logoutData, privateKeyBytes);

await fetch('/api/logout', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(signedRequest)
});
```

#### Get Current User
```javascript
const userData = {};  // Empty data

const signedRequest = await createSignedRequest(userData, privateKeyBytes);

await fetch('/api/me', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(signedRequest)
});
```

## Server-Side Verification

### 1. Timestamp Validation

The server validates that:
- Timestamp is not older than **5 minutes** (configurable via `SIGNATURE_MAX_AGE`)
- Timestamp is not in the future (allows 30 seconds clock drift)

This prevents replay attacks where an attacker captures a valid signed request and resends it later.

### 2. Signature Verification

```python
from app.auth_utils import require_signature, require_signature_with_username

# For authenticated users (with session)
@app.route('/api/protected', methods=['POST'])
@require_signature
def protected_route():
    # User's signature has been verified
    data = request.signed_data
    # ... handle request
    
# For unauthenticated users (login)
@app.route('/api/login', methods=['POST'])
@require_signature_with_username
def login():
    # Signature verified using username to lookup public key
    data = request.signed_data
    user = request.verified_user
    # ... handle login
```

### 3. Decorators

#### `@require_signature`
- Used for routes that require an active session
- Looks up user's public key from session
- Verifies signature against stored public key
- Validates timestamp
- Provides `request.signed_data` to the route

#### `@require_signature_with_username`
- Used for routes without a session (like login)
- Requires `username` in the data field
- Looks up user by username to get public key
- Verifies signature
- Provides `request.signed_data` and `request.verified_user` to the route

## Endpoint Changes

### Before (No Signatures)
```python
@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    user = User.query.get(session['user_id'])
    return jsonify({'username': user.username})
```

### After (With Signatures)
```python
@app.route('/api/me', methods=['POST'])  # Changed to POST
@require_signature
def me():
    # Signature already verified by decorator
    user = User.query.get(session['user_id'])
    return jsonify({'username': user.username})
```

**Key Changes:**
- GET → POST (to accept request body with signature)
- Added `@require_signature` decorator
- No need to check authentication (decorator handles it)
- Access data via `request.signed_data`

## Registration Flow

### Initial Registration
Registration requires signature but **no prior public key exists**. Solution:
- Client signs with the **new key pair being registered**
- Server verifies signature using `public_key` from registration data
- This proves the client possesses the private key for the public key being registered

```json
{
  "data": {
    "email": "user@example.com",
    "username": "john_doe",
    "password_hash": "...",
    "encrypted_private_key": "...",
    "public_key": "-----BEGIN PUBLIC KEY-----...",
    "encryption_iv": "...",
  },
  "signature": "...",  // Signed with private key of public_key above
  "timestamp": 1737302400
}
```

### 2FA Verification
After scanning QR code, completing registration also requires signature:
```json
{
  "data": {
    "totp_code": "123456"
  },
  "signature": "...",  // Signed with same private key
  "timestamp": 1737302401
}
```

Server verifies using the `public_key` from pending user in session.

## Security Properties

### Replay Attack Prevention
- Each request has unique timestamp
- Timestamp must be recent (< 5 minutes old)
- Old signed requests cannot be reused

### Request Integrity
- Signature covers both data and timestamp
- Any modification invalidates signature
- Man-in-the-middle cannot alter requests

### Authentication Binding
- Only private key owner can create valid signatures
- Server validates against stored public key
- Cannot forge requests without private key

### Session Hijacking Protection
- Even if session cookie is stolen, attacker needs private key
- All requests require signature verification
- Session alone is insufficient

## Error Responses

| Error | Status Code | Description |
|-------|-------------|-------------|
| `Signature is required` | 400 | Missing signature field |
| `Timestamp is required` | 400 | Missing timestamp field |
| `Data field is required` | 400 | Missing data field |
| `Invalid timestamp format` | 400 | Timestamp not an integer |
| `Invalid or expired timestamp` | 401 | Timestamp too old or in future |
| `Invalid signature` | 401 | Signature verification failed |
| `Not authenticated` | 401 | No active session |
| `User not found` | 404 | Session user no longer exists |

## Configuration

### Server Configuration (config.py)

```python
class Config:
    # Signature settings
    SIGNATURE_MAX_AGE = 300  # 5 minutes (in seconds)
```

Adjust `SIGNATURE_MAX_AGE` based on your security requirements:
- **Stricter** (60-120 seconds): Better security, less tolerance for clock drift
- **Lenient** (300-600 seconds): More tolerance for client clock issues
- **Production**: 300 seconds (5 minutes) is recommended

## Testing

### Using curl

```bash
# This will fail (no signature)
curl -X POST http://localhost:5000/api/me \
  -H "Content-Type: application/json" \
  -d '{"data": {}}'

# Generate signed request with your client library
node generate_signed_request.js | curl -X POST http://localhost:5000/api/me \
  -H "Content-Type: application/json" \
  -d @-
```

### Test Request Generation (Node.js)

```javascript
// test_request.js
const { ed25519 } = require('@noble/curves/ed25519');
const crypto = require('crypto');

// Your private key (hex)
const privateKeyHex = '...';
const privateKey = Buffer.from(privateKeyHex, 'hex');

const data = { username: 'john_doe' };
const timestamp = Math.floor(Date.now() / 1000);

const toSign = { data, timestamp };
const hash = crypto.createHash('sha256')
  .update(JSON.stringify(toSign))
  .digest();

const signature = ed25519.sign(hash, privateKey);
const signatureHex = Buffer.from(signature).toString('hex');

const request = {
  data,
  signature: signatureHex,
  timestamp
};

console.log(JSON.stringify(request, null, 2));
```

## Migration Guide

### For Existing Endpoints

1. Change GET to POST (if needed for body)
2. Add appropriate decorator
3. Update data access to use `request.signed_data`
4. Update client to send signed requests

### Example Migration

**Before:**
```python
@app.route('/api/send-message', methods=['POST'])
def send_message():
    data = request.get_json()
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    # ... process message
```

**After:**
```python
from app.auth_utils import require_signature

@app.route('/api/send-message', methods=['POST'])
@require_signature
def send_message():
    data = request.signed_data  # Already verified
    # ... process message
```

## Best Practices

1. **Always use HTTPS in production** - Signatures don't protect against passive eavesdropping
2. **Store private keys securely** - Use Web Crypto API or secure key storage
3. **Implement key rotation** - Allow users to change their keys
4. **Log signature failures** - Monitor for potential attacks
5. **Use constant-time comparison** - Prevent timing attacks (already implemented)
6. **Validate all fields** - Don't trust signed data blindly
7. **Rate limit requests** - Prevent brute force signature attempts

## Future Enhancements

- [ ] Add nonce field to prevent replay within the time window
- [ ] Implement signature algorithm versioning
- [ ] Add support for multiple active keys per user
- [ ] Implement key revocation list
- [ ] Add audit log for all signature verification failures
