# Secure Registration Flow

## Frontend → Backend Request Structure

### Registration Endpoint: `POST /api/register`

```json
{
  "email": "user@example.com",
  "username": "john_doe",
  "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "encrypted_private_key": "U2FsdGVkX1+QXd8lKc5ZmJxXvPuGcxNxvZqJ8E4K9vE8yH3mN2pQzB5wL1xY6kR7A3bN8cM9dP0eQ1fR2gS3hT4iU5jV6kW7lX8mY9nZ0oA1pB2qC3rD4sE5tF6uG7vH8wI9xJ0yK1zA2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4zA5bC6dE7fG8hI9jK0lM1nO2pQ3rS4tU5vW6xY7zA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0zA1b",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\noN5YRyYdXKRpG6pY4n8LfPj9SLn8mQ7LHFGHQSdqkKpWGcBsB9y6wKL8LzQqXz4g\nN8QtpqRqHJ4p8v9LvKGJLZZKqT6xT9yHfHQqP0nGjKvZK3p5rV8gZ9nY0vQ2wX7q\nR5tS6uU7vW8xX9yZ0aA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2mM3nN4oO5p\nP6qQ7rR8sS9tT0uU1vV2wW3xX4yY5zA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5kK6l\nL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8xX9yY0zA1bB2cC3dD4eE5fF6gG7h\nH8iI9jJ0kK1lL2mM3nN4oO5pP6qQ7rR8sS9tT0uU1vV2wW3xX4yY5zA6bB7cC8d\nD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8xX9y\nY0zA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2mM3nN4oO5pP6qQ7rR8sS9tT0u\nU1vV2wW3xX4yY5zA6bB7cC8dD9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1q\nQ2rR3sS4tT5uU6vV7wW8xX9yY0zA1bQIDAQAB\n-----END PUBLIC KEY-----",
  "encryption_iv": "a3d5f1c8b2e4a7d9c1b8e5f2a7c4d9e6",
  "signature": "3c8f9a2b1d4e5a6c7b8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
}
```

## Field Descriptions

### a. Email & Username
```json
"email": "user@example.com",
"username": "john_doe"
```
- Plain text user identifiers

### b. Password Hash (Master Key Hash)
```json
"password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```
- **Algorithm**: SHA-256 of (master_key + password)
- **Example calculation**:
  ```javascript
  const masterKey = generateMasterKey(); // Random 256-bit key
  const password = "user_password";
  const combined = masterKey + password;
  const passwordHash = sha256(combined);
  ```

### c. Encrypted Private Key
```json
"encrypted_private_key": "U2FsdGVkX1+QXd8lKc5ZmJxXvPuGcxNxvZqJ8E4K9vE..."
```
- **Algorithm**: AES-256-CBC
- **Key**: Derived from master key using PBKDF2
- **Content**: RSA private key (PEM format) encrypted
- **Encoding**: Base64

### d. Public Key
```json
"public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
```
- **Format**: PEM encoded RSA public key (2048 or 4096 bit)
- **Usage**: For encrypting messages to this user
- Stored unencrypted on server

### e. Encryption IV (Initialization Vector)
```json
"encryption_iv": "a3d5f1c8b2e4a7d9c1b8e5f2a7c4d9e6"
```
- **Size**: 16 bytes (128 bits for AES)
- **Encoding**: Hexadecimal string
- **Usage**: Required to decrypt the private key
- Generated randomly for each encryption

### f. Signature
```json
"signature": "3c8f9a2b1d4e5a6c7b8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b..."
```
- **Algorithm**: RSA signature using SHA-256
- **Data signed**: Hash of concatenated fields (a-e)
- **Process**:
  1. Concatenate: email + username + password_hash + encrypted_private_key + public_key + encryption_iv
  2. Hash with SHA-256
  3. Sign hash with private key
  4. Base64 encode signature

## Client-Side Implementation Example (JavaScript)

```javascript
// 1. Generate Ed25519 keys
const { privateKey, publicKey } = await generateEd25519KeyPair();

// 2. Generate master key
const masterKey = crypto.getRandomValues(new Uint8Array(32));

// 3. Create Argon2ID password hash
const passwordHash = await argon2id({
  password: masterKey + password,
  salt: crypto.getRandomValues(new Uint8Array(16)),
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
  type: argon2.Argon2id
});

// 4. Encrypt private key with AES-256-CBC
const iv = crypto.getRandomValues(new Uint8Array(16));
const encryptedPrivateKey = await encryptAES256CBC(
  privateKey,
  masterKey,
  iv
);

// 5. Create Ed25519 signature
const dataToSign = {
  email,
  username,
  password_hash: passwordHash,
  encrypted_private_key: encryptedPrivateKey,
  public_key: publicKey,
  encryption_iv: iv
};

const dataHash = await sha256(JSON.stringify(dataToSign));
const signature = await signWithEd25519(dataHash, privateKey);

// 6. Send to server
const registrationData = {
  ...dataToSign,
  signature: signature.toString('hex')
};

await fetch('/api/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(registrationData)
});
```

## Server-Side Verification

```python
def verify_registration(data):
    # 1. Verify signature
    data_to_verify = {
        'email': data['email'],
        'username': data['username'],
        'password_hash': data['password_hash'],
        'encrypted_private_key': data['encrypted_private_key'],
        'public_key': data['public_key'],
        'encryption_iv': data['encryption_iv']
    }
    
    data_hash = hashlib.sha256(json.dumps(data_to_verify).encode()).hexdigest()
    
    # Verify signature with public key
    public_key = load_public_key(data['public_key'])
    is_valid = verify_signature(
        public_key,
        data_hash,
        data['signature']
    )
    
    if not is_valid:
        raise ValueError("Invalid signature")
    
    # 2. Store user data
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=data['password_hash'],
        encrypted_private_key=data['encrypted_private_key'],
        public_key=data['public_key'],
        encryption_iv=data['encryption_iv']
    )
    
    return user
```

## Security Benefits

✅ **Zero-knowledge**: Server never sees the actual password  
✅ **End-to-end encryption**: Private keys encrypted client-side  
✅ **Integrity verification**: Signature prevents tampering  
✅ **Key isolation**: Each user has unique RSA key pair  
✅ **Forward secrecy**: Master key never transmitted  

## Storage in Database

```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hex
    encrypted_private_key = db.Column(db.Text, nullable=False)  # Base64 AES encrypted
    public_key = db.Column(db.Text, nullable=False)  # PEM format
    encryption_iv = db.Column(db.String(32), nullable=False)  # Hex encoded
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

## Notes

- **password_hash**: Used for authentication (like traditional password hash)
- **encrypted_private_key**: Stored encrypted, only user can decrypt with their password
- **public_key**: Used by others to encrypt messages for this user
- **encryption_iv**: Required to decrypt the private key on client side
- **signature**: Verifies that the registration data hasn't been tampered with
