# Secure Chat API - Backend

A zero-knowledge, end-to-end encrypted messaging platform API built with Flask. This backend provides secure user authentication, message storage, and conversation management with client-side encryption.

## 🔐 Security Features

- **Zero-Knowledge Architecture** - Server never sees plaintext passwords or private keys
- **Client-Side Encryption** - All sensitive data encrypted before transmission
- **Ed25519 Signatures** - Every request signed and verified
- **Argon2ID Hashing** - Password hashing with hidden salt derivation
- **2FA Authentication** - TOTP-based two-factor authentication with QR codes
- **Replay Attack Prevention** - Timestamp validation on all signed requests
- **End-to-End Encryption** - Messages encrypted between users

## 📋 Table of Contents

- [Tech Stack](#tech-stack)
- [Database Schema](#database-schema)
- [API Endpoints](#api-endpoints)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Frontend Integration](#frontend-integration)
- [Security Architecture](#security-architecture)
- [Testing](#testing)
- [Deployment](#deployment)

## 🛠 Tech Stack

### Core Framework
- **Flask 3.0.0** - Web framework
- **Python 3.8+** - Programming language
- **SQLite** - Database (easily switchable to PostgreSQL/MySQL)

### Extensions
- **Flask-SQLAlchemy 3.1.1** - ORM for database operations
- **Flask-Migrate 4.0.5** - Database migrations (Alembic wrapper)
- **Flask-CORS 4.0.0** - Cross-Origin Resource Sharing for React frontend
- **python-dotenv 1.0.0** - Environment variable management

### Security Libraries
- **pycryptodome 3.20.0** - Ed25519 signatures, AES encryption
- **argon2-cffi 23.1.0** - Argon2ID password hash validation
- **pyotp 2.9.0** - TOTP 2FA implementation
- **qrcode 7.4.2** - QR code generation for 2FA setup

## 📊 Database Schema

### Users Table
```sql
users
├── id (INTEGER, PK)
├── username (STRING, UNIQUE, MAX 24 chars)
├── email (STRING, UNIQUE)
├── created_at (DATETIME)
├── password_hash (STRING, 256) -- Argon2ID hash (client-computed)
├── encrypted_private_key (TEXT) -- AES-256 encrypted private key
├── public_key (TEXT) -- Ed25519 public key (PEM format)
├── encryption_iv (STRING, 32) -- AES IV for private key encryption
└── twofa_secret (STRING, 32) -- TOTP secret
```

### Conversations Table
```sql
conversations
├── id (INTEGER, PK)
├── name (STRING, 200, NULLABLE) -- Optional group name
└── created_at (DATETIME)
```

### Messages Table
```sql
messages
├── id (INTEGER, PK)
├── content (TEXT) -- Encrypted message content
├── created_at (DATETIME, INDEXED)
├── user_id (INTEGER, FK -> users.id)
└── conversation_id (INTEGER, FK -> conversations.id)
```

### Files Table
```sql
files
├── id (INTEGER, PK)
├── filename (STRING, 255)
├── encrypted_data (BLOB) -- Encrypted file content
├── file_size (INTEGER)
├── mime_type (STRING, 100)
├── created_at (DATETIME)
└── message_id (INTEGER, FK -> messages.id)
```

### Keys Table
```sql
keys
├── id (INTEGER, PK)
├── key_data (STRING, 500) -- Encrypted conversation key
├── created_at (DATETIME)
├── user_id (INTEGER, FK -> users.id)
├── conversation_id (INTEGER, FK -> conversations.id)
└── UNIQUE(user_id, conversation_id) -- One key per user per conversation
```

### ConversationParticipants Table
```sql
conversation_participants
├── id (INTEGER, PK)
├── user_id (INTEGER, FK -> users.id)
├── conversation_id (INTEGER, FK -> conversations.id)
├── joined_at (DATETIME)
└── UNIQUE(user_id, conversation_id)
```

### MessageReadStatus Table
```sql
message_read_statuses
├── id (INTEGER, PK)
├── message_id (INTEGER, FK -> messages.id)
├── user_id (INTEGER, FK -> users.id)
├── read_at (DATETIME)
└── UNIQUE(message_id, user_id)
```

## 🔌 API Endpoints

### Health Check
```
GET /           - API status and info
GET /health     - Health check
```

### Authentication
```
POST /api/register              - Register new user (with Ed25519 signature)
POST /api/register/verify-2fa   - Complete registration with TOTP code
POST /api/login                 - Login (requires signature + TOTP)
POST /api/logout                - Logout (requires signature)
POST /api/me                    - Get current user info (requires signature)
```

### Request Format (All Protected Endpoints)
All API requests (except registration initial) require signature verification:

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

See [SIGNATURE_PROTOCOL.md](SIGNATURE_PROTOCOL.md) for detailed documentation.

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- virtualenv (recommended)

### Step 1: Clone Repository
```bash
cd /home/ratattwg/.source/odsi_proj/backend
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Set Up Environment Variables
```bash
cp .env.example .env
```

Edit `.env` file:
```env
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here-change-in-production
DATABASE_URL=sqlite:///instance/app.db
```

### Step 5: Initialize Database
```bash
# Create database tables
flask --app run.py init-db

# OR use Flask-Migrate for production
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FLASK_APP` | Application entry point | `run.py` | Yes |
| `FLASK_ENV` | Environment (development/production) | `development` | Yes |
| `SECRET_KEY` | Flask session secret | - | Yes |
| `DATABASE_URL` | Database connection string | `sqlite:///instance/app.db` | No |

### Configuration Classes

Located in `config.py`:

- **DevelopmentConfig** - Debug mode, SQLite database
- **ProductionConfig** - HTTPS cookies, production settings
- **TestingConfig** - In-memory database, testing mode

### CORS Configuration

Edit `config.py` to add your frontend URLs:

```python
CORS_ORIGINS = [
    'http://localhost:3000',  # React dev server (Create React App)
    'http://localhost:5173',  # Vite dev server
    'https://yourapp.com'     # Production frontend
]
```

## 🚀 Running the Application

### Development Server
```bash
# Activate virtual environment
source venv/bin/activate

# Run Flask development server
flask --app run.py run

# Or with debug mode
flask --app run.py run --debug

# Custom host and port
flask --app run.py run --host=0.0.0.0 --port=5000
```

### Production Server
```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app()'

# Or with environment variable
gunicorn -w 4 -b 0.0.0.0:5000 'app:create_app("production")'
```

### Database Commands
```bash
# Initialize database
flask --app run.py init-db

# Seed with sample data (development only)
flask --app run.py seed-db

# Database migrations
flask db migrate -m "Description of changes"
flask db upgrade
flask db downgrade
```

## 🎨 Frontend Integration (React + Tailwind)

### Setup Guide for Frontend Developers

This backend is designed to work with a React frontend using Tailwind CSS. Here's what you need to know:

### 1. Required JavaScript Libraries

```bash
# Core libraries
npm install @noble/curves @noble/hashes

# UI libraries (optional but recommended)
npm install qrcode.react
npm install react-toastify
```

### 2. Environment Configuration

Create `.env` in your React project:

```env
VITE_API_URL=http://localhost:5000
# OR for Create React App
REACT_APP_API_URL=http://localhost:5000
```

### 3. API Client Setup

Create `src/utils/api.js`:

```javascript
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export const apiClient = {
  baseURL: API_URL,
  
  async request(endpoint, options = {}) {
    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      credentials: 'include', // Important for session cookies
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Request failed');
    }
    
    return response.json();
  }
};
```

### 4. Cryptography Utilities

Create `src/utils/crypto.js`:

```javascript
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { argon2id } from '@noble/hashes/argon2';

/**
 * Generate Ed25519 keypair
 */
export async function generateKeypair() {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  
  return { privateKey, publicKey };
}

/**
 * Export public key to PEM format
 */
export function publicKeyToPEM(publicKey) {
  const base64 = btoa(String.fromCharCode(...publicKey));
  return `-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA${base64}\n-----END PUBLIC KEY-----`;
}

/**
 * Derive salt from password and email
 */
export async function deriveSalt(password, email) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + email);
  const hash = sha256(data);
  return hash.slice(0, 16); // First 16 bytes
}

/**
 * Hash password with Argon2ID
 */
export async function hashPassword(password, email) {
  const salt = await deriveSalt(password, email);
  
  const hash = argon2id(password, salt, {
    m: 16384,  // 16 MB memory
    t: 2,      // 2 iterations
    p: 1       // 1 parallelism
  });
  
  // Return as hex string
  return Array.from(hash)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Encrypt private key with AES-256
 */
export async function encryptPrivateKey(privateKey, masterKey, iv) {
  const algorithm = { name: 'AES-GCM', iv };
  
  const encrypted = await crypto.subtle.encrypt(
    algorithm,
    masterKey,
    privateKey
  );
  
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

/**
 * Sign data with Ed25519
 */
export async function signData(data, privateKey) {
  const encoder = new TextEncoder();
  const dataString = JSON.stringify(data);
  const dataHash = sha256(encoder.encode(dataString));
  
  const signature = ed25519.sign(dataHash, privateKey);
  
  return Array.from(signature)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create signed request for API
 */
export async function createSignedRequest(data, privateKey) {
  const timestamp = Math.floor(Date.now() / 1000);
  
  const toSign = { data, timestamp };
  const signature = await signData(toSign, privateKey);
  
  return {
    data,
    signature,
    timestamp
  };
}
```

### 5. Authentication Hook

Create `src/hooks/useAuth.js`:

```javascript
import { useState, useEffect, createContext, useContext } from 'react';
import { apiClient } from '../utils/api';
import { createSignedRequest } from '../utils/crypto';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [privateKey, setPrivateKey] = useState(null);

  useEffect(() => {
    checkAuth();
  }, []);

  async function checkAuth() {
    try {
      // Load private key from secure storage
      const storedKey = localStorage.getItem('privateKey');
      if (!storedKey) {
        setLoading(false);
        return;
      }
      
      const keyBytes = new Uint8Array(JSON.parse(storedKey));
      setPrivateKey(keyBytes);
      
      // Verify session with server
      const signedRequest = await createSignedRequest({}, keyBytes);
      const data = await apiClient.request('/api/me', {
        method: 'POST',
        body: JSON.stringify(signedRequest)
      });
      
      setUser(data);
    } catch (error) {
      console.error('Auth check failed:', error);
      localStorage.removeItem('privateKey');
    } finally {
      setLoading(false);
    }
  }

  async function login(username, passwordHash, totpCode, privateKey) {
    const loginData = { username, password_hash: passwordHash, totp_code: totpCode };
    const signedRequest = await createSignedRequest(loginData, privateKey);
    
    const data = await apiClient.request('/api/login', {
      method: 'POST',
      body: JSON.stringify(signedRequest)
    });
    
    setUser(data.user);
    setPrivateKey(privateKey);
    localStorage.setItem('privateKey', JSON.stringify(Array.from(privateKey)));
    
    return data;
  }

  async function logout() {
    if (!privateKey) return;
    
    const signedRequest = await createSignedRequest({}, privateKey);
    await apiClient.request('/api/logout', {
      method: 'POST',
      body: JSON.stringify(signedRequest)
    });
    
    setUser(null);
    setPrivateKey(null);
    localStorage.removeItem('privateKey');
  }

  return (
    <AuthContext.Provider value={{ user, loading, privateKey, login, logout, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
```

### 6. Registration Component Example

Create `src/components/Register.jsx`:

```javascript
import { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { generateKeypair, publicKeyToPEM, hashPassword, encryptPrivateKey, signData } from '../utils/crypto';
import { apiClient } from '../utils/api';

export function Register() {
  const [step, setStep] = useState(1); // 1: form, 2: QR code
  const [qrCode, setQrCode] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: ''
  });

  async function handleRegister(e) {
    e.preventDefault();
    
    if (formData.password !== formData.confirmPassword) {
      alert('Passwords do not match');
      return;
    }

    try {
      // 1. Generate keypair
      const { privateKey, publicKey } = await generateKeypair();
      
      // 2. Hash password with Argon2ID
      const password_hash = await hashPassword(formData.password, formData.email);
      
      // 3. Encrypt private key
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
      
      const masterKey = await crypto.subtle.importKey(
        'raw',
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(formData.password)),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      
      const encrypted_private_key = await encryptPrivateKey(privateKey, masterKey, iv);
      const public_key = publicKeyToPEM(publicKey);
      
      // 4. Prepare data to sign
      const registrationData = {
        email: formData.email,
        username: formData.username,
        password_hash,
        encrypted_private_key,
        public_key,
        encryption_iv: ivHex
      };
      
      // 5. Sign registration data
      const timestamp = Math.floor(Date.now() / 1000);
      const toSign = { data: registrationData, timestamp };
      const signature = await signData(toSign, privateKey);
      
      // 6. Send to server
      const response = await apiClient.request('/api/register', {
        method: 'POST',
        body: JSON.stringify({
          data: registrationData,
          signature,
          timestamp
        })
      });
      
      // 7. Show QR code
      setQrCode(response.qr_code);
      setTotpSecret(response.secret);
      setStep(2);
      
      // Store private key temporarily for 2FA verification
      sessionStorage.setItem('tempPrivateKey', JSON.stringify(Array.from(privateKey)));
      
    } catch (error) {
      alert(error.message);
    }
  }

  async function handleVerify2FA(e) {
    e.preventDefault();
    
    const totpCode = e.target.totpCode.value;
    const privateKey = new Uint8Array(JSON.parse(sessionStorage.getItem('tempPrivateKey')));
    
    try {
      const timestamp = Math.floor(Date.now() / 1000);
      const toSign = { data: { totp_code: totpCode }, timestamp };
      const signature = await signData(toSign, privateKey);
      
      await apiClient.request('/api/register/verify-2fa', {
        method: 'POST',
        body: JSON.stringify({
          data: { totp_code: totpCode },
          signature,
          timestamp
        })
      });
      
      // Registration complete
      sessionStorage.removeItem('tempPrivateKey');
      alert('Registration successful!');
      
    } catch (error) {
      alert(error.message);
    }
  }

  if (step === 2) {
    return (
      <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-lg">
        <h2 className="text-2xl font-bold mb-4">Scan QR Code</h2>
        <div className="flex justify-center mb-4">
          <img src={qrCode} alt="2FA QR Code" className="w-64 h-64" />
        </div>
        <p className="text-sm text-gray-600 mb-4">
          Secret: <code className="bg-gray-100 px-2 py-1 rounded">{totpSecret}</code>
        </p>
        <form onSubmit={handleVerify2FA}>
          <input
            type="text"
            name="totpCode"
            placeholder="Enter 6-digit code"
            className="w-full px-4 py-2 border rounded-lg mb-4"
            maxLength={6}
            required
          />
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700"
          >
            Verify & Complete Registration
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-6">Register</h2>
      <form onSubmit={handleRegister} className="space-y-4">
        <input
          type="email"
          placeholder="Email"
          className="w-full px-4 py-2 border rounded-lg"
          value={formData.email}
          onChange={(e) => setFormData({...formData, email: e.target.value})}
          required
        />
        <input
          type="text"
          placeholder="Username (max 24 chars)"
          className="w-full px-4 py-2 border rounded-lg"
          maxLength={24}
          value={formData.username}
          onChange={(e) => setFormData({...formData, username: e.target.value})}
          required
        />
        <input
          type="password"
          placeholder="Password"
          className="w-full px-4 py-2 border rounded-lg"
          value={formData.password}
          onChange={(e) => setFormData({...formData, password: e.target.value})}
          required
        />
        <input
          type="password"
          placeholder="Confirm Password"
          className="w-full px-4 py-2 border rounded-lg"
          value={formData.confirmPassword}
          onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})}
          required
        />
        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700"
        >
          Register
        </button>
      </form>
    </div>
  );
}
```

### 7. Tailwind CSS Setup

```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

Edit `tailwind.config.js`:

```javascript
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#667eea',
        secondary: '#764ba2',
      }
    },
  },
  plugins: [],
}
```

### 8. Recommended Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── Register.jsx
│   │   ├── Login.jsx
│   │   ├── ChatRoom.jsx
│   │   └── MessageList.jsx
│   ├── hooks/
│   │   ├── useAuth.js
│   │   └── useMessages.js
│   ├── utils/
│   │   ├── api.js
│   │   └── crypto.js
│   ├── App.jsx
│   └── main.jsx
├── public/
├── package.json
└── tailwind.config.js
```

## 🔒 Security Architecture

### Zero-Knowledge Design

1. **Password Hashing** (Client-Side)
   - Salt derived from `password + email` (deterministic, hidden)
   - Argon2ID with parameters: `m=16384, t=2, p=1`
   - Only hash transmitted to server (64 hex chars)
   - Server stores hash, cannot reverse to password

2. **Private Key Encryption**
   - Ed25519 private key encrypted with user's master key
   - AES-256-GCM encryption with random IV
   - Server stores encrypted key, cannot decrypt it
   - User decrypts on login with password-derived master key

3. **Request Signing**
   - Every request signed with Ed25519 private key
   - Signature includes timestamp to prevent replay
   - Server verifies using stored public key
   - 5-minute timestamp window (configurable)

4. **End-to-End Message Encryption**
   - Messages encrypted client-side before sending
   - Each conversation has unique encryption key
   - Keys stored encrypted per-user in database
   - Only conversation participants can decrypt

### Authentication Flow

1. **Registration**
   ```
   Client                                  Server
     |                                       |
     |-- Generate Ed25519 keypair           |
     |-- Hash password with Argon2ID        |
     |-- Encrypt private key with AES       |
     |-- Sign registration data             |
     |                                       |
     |------- POST /api/register ---------> |
     |       (signature verified)           |
     |                                       |
     | <----- QR code for 2FA ------------- |
     |                                       |
     |-- Scan QR, enter TOTP code           |
     |                                       |
     |-- POST /api/register/verify-2fa ---> |
     |       (signature + TOTP verified)    |
     |                                       |
     | <----- User created ----------------- |
     |       (session established)          |
   ```

2. **Login**
   ```
   Client                                  Server
     |                                       |
     |-- Enter username + password          |
     |-- Load private key from storage      |
     |-- Hash password with Argon2ID        |
     |-- Get TOTP code from authenticator   |
     |                                       |
     |------- POST /api/login ------------> |
     |       (signed with private key)      |
     |                                       |
     |       Server verifies:               |
     |       - Signature valid?             |
     |       - Password hash matches?       |
     |       - TOTP code correct?           |
     |                                       |
     | <----- Session established --------- |
     |       (returns user data)            |
   ```

### Threat Model

**Protected Against:**
- ✅ Password theft (server never sees plaintext)
- ✅ Private key theft (encrypted with user password)
- ✅ Replay attacks (timestamp validation)
- ✅ Man-in-the-middle (HTTPS + signature verification)
- ✅ Session hijacking (requires private key for requests)
- ✅ Database breach (passwords hashed, keys encrypted)

**Requires Additional Protection:**
- ⚠️ Client-side malware (can steal decrypted keys from memory)
- ⚠️ Phishing (users must verify domain)
- ⚠️ Device theft (secure key storage recommended)

## 🧪 Testing

### Manual API Testing

Using curl:

```bash
# Health check
curl http://localhost:5000/health

# Registration (requires signature - use frontend)
# See SIGNATURE_PROTOCOL.md for manual testing
```

### Unit Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest

# With coverage
pytest --cov=app tests/
```

### Load Testing

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/locustfile.py --host=http://localhost:5000
```

## 🚀 Deployment

### Production Checklist

- [ ] Set `FLASK_ENV=production`
- [ ] Generate strong `SECRET_KEY` (32+ random bytes)
- [ ] Use PostgreSQL or MySQL instead of SQLite
- [ ] Enable `SESSION_COOKIE_SECURE=True` (requires HTTPS)
- [ ] Set up proper CORS origins (your production domain)
- [ ] Configure reverse proxy (Nginx/Apache)
- [ ] Set up SSL/TLS certificates (Let's Encrypt)
- [ ] Enable database backups
- [ ] Set up monitoring and logging
- [ ] Configure firewall rules
- [ ] Use environment variables for secrets (not .env file)
- [ ] Set up CI/CD pipeline

### Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:create_app('production')"]
```

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=postgresql://user:pass@db:5432/chatapp
    depends_on:
      - db
  
  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=chatapp
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

Run:
```bash
docker-compose up -d
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name api.yourapp.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📚 Additional Documentation

- [SIGNATURE_PROTOCOL.md](SIGNATURE_PROTOCOL.md) - Detailed signature verification protocol
- [CLIENT_HASHING.md](CLIENT_HASHING.md) - Client-side password hashing guide
- [sample_register_request.json](sample_register_request.json) - Example registration request

## 🤝 Contributing

### Development Workflow

1. Create feature branch
2. Make changes
3. Run tests
4. Submit pull request

### Code Style

- Follow PEP 8 for Python code
- Use type hints where appropriate
- Add docstrings to functions
- Keep functions focused and small

## 📝 License

[Add your license here]

## 🐛 Known Issues

- Session cookies not supported in Safari Private Mode
- Timestamp validation may fail with significant clock drift
- SQLite not recommended for production (use PostgreSQL)

## 📞 Support

For questions or issues:
- Open an issue on GitHub
- Contact: [your-email@example.com]

## 🔄 Changelog

### Version 1.0.0 (2026-01-19)
- Initial release
- Zero-knowledge authentication
- Ed25519 signature verification
- Argon2ID password hashing
- 2FA with TOTP
- CORS support for React
- Complete message encryption system

---

**Built with ❤️ for privacy and security**
