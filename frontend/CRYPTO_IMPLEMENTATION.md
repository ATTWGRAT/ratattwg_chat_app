# Cryptographic Implementation Summary

## Security Architecture (Compliant with Specification)

### 1. Key Generation (Ed25519)
- Client generates Ed25519 key pair for digital signatures
- Private key: 32 bytes, used for signing all API requests
- Public key: Stored on server in PEM format

### 2. Master Key Generation (PBKDF2)
```
Master Key = PBKDF2(password, email, 100000 iterations, SHA-256)
```
- **Payload**: User's plain password
- **Salt**: User's email address
- **Output**: 32-byte Master Key
- **Purpose**: Used for encrypting the private key

### 3. Password Hashing (Argon2id)
```
Password Hash = Argon2ID(Master Key, password, 3 iterations, 64MB memory)
```
- **Payload**: Master Key (32 bytes)
- **Salt**: Original password (hashed to 16 bytes)
- **Output**: 32-byte hex hash sent to server
- **Purpose**: Server-side authentication without exposing password or Master Key

### 4. Private Key Encryption (AES-256-GCM)
```
Encrypted Private Key = AES-GCM(Private Key, Master Key, IV)
```
- **Key**: Master Key (32 bytes)
- **IV**: 12 bytes = 8 random bytes + 4 timestamp bytes
- **Timestamp Component**: Ensures IV uniqueness even with same Master Key
- **Purpose**: Secure storage of private key, decryptable only with correct password

## Data Flow

### Registration
1. Generate Ed25519 key pair
2. Generate Master Key from password + email
3. Hash Master Key with Argon2id (salt: password)
4. Encrypt private key with Master Key (time-based IV)
5. Send to server: username, email, password_hash, encrypted_private_key, public_key, IV
6. Store locally: encrypted_private_key, IV, email
7. Complete 2FA verification
8. **Store in memory**: Private Key + Master Key

### Login
1. Retrieve from localStorage: encrypted_private_key, IV, email
2. Generate Master Key from password + email
3. Hash Master Key with Argon2id (salt: password)
4. Decrypt private key with Master Key
5. Sign login request with private key
6. Send to server: username, password_hash, totp_code (all signed)
7. **Store in memory**: Private Key + Master Key

### API Requests
All protected endpoints require:
1. Sign request with private key (Ed25519)
2. Include timestamp to prevent replay attacks
3. Server verifies signature with stored public key

## Memory-Only Storage (Zero Knowledge)

### What's stored in memory:
- ✅ Private Key (decrypted, Uint8Array)
- ✅ Master Key (Uint8Array)
- ✅ User session data

### What's stored in localStorage:
- ✅ Encrypted private key (hex string)
- ✅ IV (hex string)
- ✅ Email (for Master Key derivation)

### What's NEVER stored:
- ❌ Plain password
- ❌ Decrypted private key on disk
- ❌ Master Key on disk

## IV Uniqueness Guarantee

The IV generation combines:
- 8 bytes of cryptographically secure random data
- 4 bytes derived from `Date.now()` timestamp

This ensures that even if the same Master Key is used multiple times, the IV will always be unique due to:
1. Different random bytes each time
2. Different timestamp (millisecond precision)

Formula:
```
IV[0-7]   = crypto.getRandomValues()  // 8 random bytes
IV[8-11]  = timestamp bytes           // 4 bytes from Date.now()
```

## Security Properties

✅ **Zero-Knowledge**: Server never sees plain password or unencrypted private key
✅ **Forward Secrecy**: Each session has unique signatures with timestamps
✅ **Replay Protection**: Timestamp validation (5-minute window)
✅ **Device-Based**: Private key encrypted per-device
✅ **2FA**: TOTP required for all authentications
✅ **Deterministic Derivation**: Master Key can be recreated from password + email
✅ **IV Uniqueness**: Time component prevents IV reuse
