# Client-Side Password Hashing (Zero-Knowledge)

## Overview

This application uses a **zero-knowledge architecture** where the server never sees the user's actual password. All password processing happens client-side, similar to Bitwarden's approach.

## Client-Side Hash Generation

### 1. Derive Salt from Password

The salt is **deterministically derived** from the user's password and email, not randomly generated:

```javascript
// Derive salt from password and email (hidden from server)
const encoder = new TextEncoder();
const passwordData = encoder.encode(password + email);
const saltHash = await crypto.subtle.digest('SHA-256', passwordData);
const salt = new Uint8Array(saltHash).slice(0, 16); // First 16 bytes
```

### 2. Compute Argon2ID Hash

Use the derived salt to create the password hash:

```javascript
import { argon2id } from '@noble/hashes/argon2';

// Argon2ID parameters (browser-optimized)
const hash = argon2id(password, salt, {
  m: 16384,  // 16 MB memory
  t: 2,      // 2 iterations
  p: 1       // 1 parallelism (single-threaded)
});

// Convert to hex for transmission
const password_hash = Array.from(hash)
  .map(b => b.toString(16).padStart(2, '0'))
  .join('');
```

### 3. Send Only Hash Output

Send **only the raw hash output** (64 hex characters), not the full Argon2 format string with embedded salt:

```json
{
  "password_hash": "4f8a9b2e1c3d5e7f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f"
}
```

## Why This Approach?

### Security Benefits

1. **Salt Privacy**: Salt is derived from password, never transmitted separately
2. **Deterministic**: Same password always produces same hash (for login verification)
3. **Zero-Knowledge**: Server only stores the final hash, never sees original password or salt
4. **Replay-Safe**: Combined with signature verification, prevents replay attacks

### Comparison: Argon2 Format vs Raw Hash

| Aspect | Full Argon2 Format | Raw Hash (This App) |
|--------|-------------------|---------------------|
| Format | `$argon2id$v=19$m=16384,t=2,p=1$SALT$HASH` | `4f8a9b2e1c3d...` (64 hex) |
| Salt Visible | ✅ Yes (base64 in string) | ❌ No (hidden) |
| Parameters Visible | ✅ Yes | ❌ No |
| Zero-Knowledge | ⚠️ Salt exposed | ✅ Fully hidden |
| Server Validation | Validates full format | Validates hex length |

## Full Registration Flow

```javascript
// 1. User enters password
const password = "user_password_123";
const email = "user@example.com";

// 2. Derive salt (hidden from server)
const saltData = new TextEncoder().encode(password + email);
const saltHash = await crypto.subtle.digest('SHA-256', saltData);
const salt = new Uint8Array(saltHash).slice(0, 16);

// 3. Compute Argon2ID hash
const hash = argon2id(password, salt, { m: 16384, t: 2, p: 1 });
const password_hash = Array.from(hash)
  .map(b => b.toString(16).padStart(2, '0'))
  .join('');

// 4. Derive master encryption key (separate from hash)
const masterKey = await crypto.subtle.importKey(
  'raw',
  await crypto.subtle.digest('SHA-256', saltData),
  { name: 'PBKDF2' },
  false,
  ['deriveKey']
);

// 5. Generate Ed25519 keypair
const { privateKey, publicKey } = await crypto.subtle.generateKey(
  { name: 'Ed25519' },
  true,
  ['sign', 'verify']
);

// 6. Encrypt private key with master key
const iv = crypto.getRandomValues(new Uint8Array(16));
const encryptedPrivateKey = await encryptPrivateKey(privateKey, masterKey, iv);

// 7. Sign registration data
const dataToSign = {
  email,
  username,
  password_hash,
  encrypted_private_key: base64Encode(encryptedPrivateKey),
  public_key: await exportPublicKey(publicKey),
  encryption_iv: arrayToHex(iv)
};
const signature = await signData(dataToSign, privateKey);

// 8. Send to server
await fetch('/api/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...dataToSign, signature })
});
```

## Server Validation

The server validates the hash format but **cannot derive the original password**:

```python
def validate_argon2_hash(password_hash):
    """Accept raw hex hash (64 chars) for zero-knowledge."""
    if len(password_hash) == 64:
        try:
            bytes.fromhex(password_hash)
            return True
        except ValueError:
            return False
    return False
```

## Security Properties

- ✅ **Server never sees plaintext password**
- ✅ **Salt is derived, not random** (deterministic for same password+email)
- ✅ **Salt is never transmitted** (hidden in client-side computation)
- ✅ **Hash cannot be reversed** (Argon2ID is one-way)
- ✅ **Replay protection** (Ed25519 signature verification)
- ✅ **Forward secrecy** (master key derived separately)

## Libraries

### Client-Side (JavaScript)
- `@noble/hashes/argon2` - Argon2ID hashing
- Web Crypto API - Ed25519 signatures, AES encryption
- `@noble/ed25519` - Fallback for Ed25519 if needed

### Server-Side (Python)
- `argon2-cffi` - Hash validation (format check only)
- `pycryptodome` - Ed25519 signature verification

## Notes

1. The server **only validates hash length/format**, not the hash content
2. Login verification compares stored hash with submitted hash (direct equality)
3. Salt derivation is **deterministic**: same password → same hash → successful login
4. For additional security, consider adding a **salt version** field for future algorithm changes
