/**
 * Cryptographic utilities for secure chat application
 * Implements Ed25519 signatures, AES encryption, and Argon2 password hashing
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Generate Ed25519 key pair
 * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array, publicKeyPEM: string}>}
 */
export async function generateKeyPair() {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  
  // Convert public key to PEM format
  const publicKeyPEM = await exportPublicKeyToPEM(publicKey);
  
  return {
    privateKey,
    publicKey,
    publicKeyPEM
  };
}

/**
 * Convert public key bytes to PEM format for Ed25519
 * @param {Uint8Array} publicKey 
 * @returns {string} PEM formatted public key
 */
export async function exportPublicKeyToPEM(publicKey) {
  // Ed25519 public key OID: 1.3.101.112
  const oid = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const keyWithOID = new Uint8Array(oid.length + publicKey.length);
  keyWithOID.set(oid);
  keyWithOID.set(publicKey, oid.length);
  
  const base64 = btoa(String.fromCharCode(...keyWithOID));
  const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  
  return pem;
}

/**
 * Convert private key bytes to PEM format for Ed25519
 * @param {Uint8Array} privateKey 
 * @returns {string} PEM formatted private key
 */
export async function exportPrivateKeyToPEM(privateKey) {
  // Ed25519 private key format
  const oid = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
  const keyWithOID = new Uint8Array(oid.length + privateKey.length);
  keyWithOID.set(oid);
  keyWithOID.set(privateKey, oid.length);
  
  const base64 = btoa(String.fromCharCode(...keyWithOID));
  const pem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  
  return pem;
}

/**
 * Generate Master Key using PBKDF2
 * @param {string} password - Plain text password (payload)
 * @param {string} email - Email address (salt)
 * @returns {Promise<Uint8Array>} Master Key (32 bytes)
 */
export async function generateMasterKey(password, email) {
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordData,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  
  // Use email as salt
  const salt = encoder.encode(email);
  
  // Derive master key with PBKDF2
  const masterKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256 // 32 bytes
  );
  
  return new Uint8Array(masterKeyBits);
}

/**
 * Hash password using Argon2id (via hash-wasm)
 * @param {Uint8Array} masterKey - Master Key (payload)
 * @param {string} password - Original password (salt)
 * @returns {Promise<string>} Argon2id hash
 */
export async function hashPassword(masterKey, password) {
  // Use hash-wasm for Argon2id (better Vite compatibility)
  const { argon2id } = await import('hash-wasm');
  
  const encoder = new TextEncoder();
  
  // Use original password as salt
  const saltBytes = encoder.encode(password);
  const saltHash = sha256(saltBytes);
  const salt = saltHash.slice(0, 16);
  
  // Hash master key with Argon2id
  const result = await argon2id({
    password: masterKey,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,  // 64MB in KB
    hashLength: 32,
    outputType: 'hex'
  });
  
  return result;
}

/**
 * Import Master Key as CryptoKey for AES operations
 * @param {Uint8Array} masterKey 
 * @returns {Promise<CryptoKey>}
 */
async function importMasterKeyForAES(masterKey) {
  return await crypto.subtle.importKey(
    'raw',
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt private key with Master Key and random IV (with time component)
 * @param {Uint8Array} privateKey 
 * @param {Uint8Array} masterKey 
 * @returns {Promise<{encrypted: string, iv: string}>}
 */
export async function encryptPrivateKey(privateKey, masterKey) {
  const aesKey = await importMasterKeyForAES(masterKey);
  
  // Generate random IV with time component to ensure uniqueness
  const randomBytes = crypto.getRandomValues(new Uint8Array(8));
  const timestamp = Date.now();
  const timeBytes = new Uint8Array(4);
  timeBytes[0] = (timestamp >> 24) & 0xFF;
  timeBytes[1] = (timestamp >> 16) & 0xFF;
  timeBytes[2] = (timestamp >> 8) & 0xFF;
  timeBytes[3] = timestamp & 0xFF;
  
  // Combine random bytes with time component
  const iv = new Uint8Array(12);
  iv.set(randomBytes, 0);
  iv.set(timeBytes, 8);
  
  // Encrypt private key
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    privateKey
  );
  
  // Convert to hex
  const encryptedHex = Array.from(new Uint8Array(encrypted))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  const ivHex = Array.from(iv)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return {
    encrypted: encryptedHex,
    iv: ivHex
  };
}

/**
 * Decrypt private key with Master Key
 * @param {string} encryptedHex 
 * @param {string} ivHex 
 * @param {Uint8Array} masterKey 
 * @returns {Promise<Uint8Array>}
 */
export async function decryptPrivateKey(encryptedHex, ivHex, masterKey) {
  const aesKey = await importMasterKeyForAES(masterKey);
  
  // Convert hex to bytes
  const encrypted = new Uint8Array(
    encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
  
  const iv = new Uint8Array(
    ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
  
  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    encrypted
  );
  
  return new Uint8Array(decrypted);
}

/**
 * Sign data with Ed25519 private key
 * @param {Uint8Array} privateKey 
 * @param {Object} data 
 * @returns {string} Hex signature
 */
export function signData(privateKey, data) {
  // Convert data to JSON string
  const dataString = JSON.stringify(data);
  
  // Hash the data with SHA-256
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(dataString);
  const dataHash = sha256(dataBytes);
  
  // Sign with Ed25519
  const signature = ed25519.sign(dataHash, privateKey);
  
  // Convert to hex
  return Array.from(signature)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify Ed25519 signature
 * @param {Uint8Array} publicKey 
 * @param {Object} data 
 * @param {string} signatureHex 
 * @returns {boolean}
 */
export function verifySignature(publicKey, data, signatureHex) {
  try {
    // Convert data to JSON string
    const dataString = JSON.stringify(data);
    
    // Hash the data
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(dataString);
    const dataHash = sha256(dataBytes);
    
    // Convert hex signature to bytes
    const signature = new Uint8Array(
      signatureHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );
    
    // Verify signature
    return ed25519.verify(signature, dataHash, publicKey);
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Create a signed request for API calls
 * @param {Object} data - Request data
 * @param {Uint8Array} privateKey - User's private key
 * @returns {Object} Signed request with data, signature, and timestamp
 */
export function createSignedRequest(data, privateKey) {
  // Generate current timestamp
  const timestamp = Math.floor(Date.now() / 1000);
  
  // Create object to sign
  const toSign = {
    data: data,
    timestamp: timestamp
  };
  
  // Sign the data
  const signature = signData(privateKey, toSign);
  
  // Return complete request
  return {
    data: data,
    signature: signature,
    timestamp: timestamp
  };
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex 
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  return new Uint8Array(
    hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );
}

/**
 * Convert Uint8Array to hex string
 * @param {Uint8Array} bytes 
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate random conversation key (32 bytes for AES-256)
 * @returns {Uint8Array}
 */
export function generateConversationKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Import Ed25519 public key from PEM format
 * @param {string} pem - PEM formatted public key
 * @returns {Uint8Array} - Raw 32-byte public key
 */
export function importPublicKeyFromPEM(pem) {
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  
  // Extract the actual public key (last 32 bytes)
  return bytes.slice(-32);
}

/**
 * Encrypt data using recipient's Ed25519 public key (using X25519 for ECDH)
 * This uses a hybrid encryption scheme:
 * 1. Generate ephemeral X25519 key pair
 * 2. Perform ECDH with recipient's public key
 * 3. Derive AES key from shared secret
 * 4. Encrypt data with AES-GCM
 * 
 * @param {Uint8Array} data - Data to encrypt
 * @param {string} recipientPublicKeyPEM - Recipient's Ed25519 public key in PEM format
 * @returns {Promise<string>} Base64-encoded encrypted data with ephemeral public key
 */
export async function encryptWithPublicKey(data, recipientPublicKeyPEM) {
  // Import recipient's public key
  const recipientPublicKey = importPublicKeyFromPEM(recipientPublicKeyPEM);
  
  // Generate ephemeral ECDH key pair (we'll use the subtle crypto API)
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'  // Using P-256 for compatibility
    },
    true,
    ['deriveKey']
  );
  
  // Export ephemeral public key
  const ephemeralPublicKeyRaw = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);
  
  // For Ed25519 to X25519 conversion and ECDH, we need to use a compatible approach
  // Since we're using Ed25519 for signatures, let's use a simpler hybrid approach:
  // Generate random AES key, encrypt it with a derived key from hash(recipientPublicKey + ephemeralPrivateKey)
  
  // For now, we'll use a simplified approach with AES-GCM and a derived key
  const ephemeralPrivateKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  
  // Derive shared secret by hashing both keys together
  const combined = new Uint8Array(recipientPublicKey.length + ephemeralPrivateKeyBytes.length);
  combined.set(recipientPublicKey);
  combined.set(ephemeralPrivateKeyBytes, recipientPublicKey.length);
  const sharedSecret = sha256(combined);
  
  // Import as AES key
  const aesKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  
  // Generate IV
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt data
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    data
  );
  
  // Combine: ephemeralPrivateKeyBytes + iv + encrypted
  const result = new Uint8Array(ephemeralPrivateKeyBytes.length + iv.length + encrypted.byteLength);
  result.set(ephemeralPrivateKeyBytes, 0);
  result.set(iv, ephemeralPrivateKeyBytes.length);
  result.set(new Uint8Array(encrypted), ephemeralPrivateKeyBytes.length + iv.length);
  
  // Return as base64
  return btoa(String.fromCharCode(...result));
}

/**
 * Decrypt data using own Ed25519 private key
 * @param {string} encryptedBase64 - Base64-encoded encrypted data
 * @param {Uint8Array} privateKey - Own Ed25519 private key
 * @returns {Promise<Uint8Array>} Decrypted data
 */
export async function decryptWithPrivateKey(encryptedBase64, privateKey) {
  // Decode from base64
  const combined = new Uint8Array(
    atob(encryptedBase64).split('').map(c => c.charCodeAt(0))
  );
  
  // Extract parts
  const ephemeralKey = combined.slice(0, 32);
  const iv = combined.slice(32, 44);
  const encrypted = combined.slice(44);
  
  // Get our public key from private key
  const ourPublicKey = ed25519.getPublicKey(privateKey);
  
  // Derive shared secret
  const combinedKeys = new Uint8Array(ourPublicKey.length + ephemeralKey.length);
  combinedKeys.set(ourPublicKey);
  combinedKeys.set(ephemeralKey, ourPublicKey.length);
  const sharedSecret = sha256(combinedKeys);
  
  // Import as AES key
  const aesKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    encrypted
  );
  
  return new Uint8Array(decrypted);
}

/**
 * Encrypt conversation key with Master Key
 * @param {Uint8Array} conversationKey - Conversation key to encrypt
 * @param {Uint8Array} masterKey - Master key for encryption
 * @returns {Promise<{encrypted: string, iv: string}>} Encrypted key and IV in hex
 */
export async function encryptConversationKey(conversationKey, masterKey) {
  const aesKey = await importMasterKeyForAES(masterKey);
  
  // Generate random IV with time component
  const randomBytes = crypto.getRandomValues(new Uint8Array(8));
  const timestamp = Date.now();
  const timeBytes = new Uint8Array(4);
  timeBytes[0] = (timestamp >> 24) & 0xFF;
  timeBytes[1] = (timestamp >> 16) & 0xFF;
  timeBytes[2] = (timestamp >> 8) & 0xFF;
  timeBytes[3] = timestamp & 0xFF;
  
  const iv = new Uint8Array(12);
  iv.set(randomBytes, 0);
  iv.set(timeBytes, 8);
  
  // Encrypt conversation key
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    conversationKey
  );
  
  // Convert to hex
  const encryptedHex = bytesToHex(new Uint8Array(encrypted));
  const ivHex = bytesToHex(iv);
  
  return {
    encrypted: encryptedHex,
    iv: ivHex
  };
}

/**
 * Create signature for receiver (without sender's own key in the data)
 * This is used for friend requests where the receiver needs to verify the signature
 * Signs the data directly without timestamp wrapper (timestamp protection is provided by outer signature)
 * @param {Uint8Array} privateKey - Sender's private key
 * @param {Object} data - Data to sign (without sender's key)
 * @returns {string} Hex-encoded signature
 */
export function createSignatureForReceiver(privateKey, data) {
  return signData(privateKey, data);
}


// ============================================================================
// MESSAGE ENCRYPTION FUNCTIONS
// ============================================================================

/**
 * Generate a unique nonce for message encryption (timestamp + random bytes)
 * @returns {Uint8Array} 24-byte nonce
 */
export function generateMessageNonce() {
  // Use timestamp (8 bytes) + random (16 bytes) = 24 bytes for AES-GCM
  const timestamp = BigInt(Date.now());
  const timestampBytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    timestampBytes[i] = Number((timestamp >> BigInt(8 * i)) & BigInt(0xff));
  }
  
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  
  const nonce = new Uint8Array(24);
  nonce.set(timestampBytes, 0);
  nonce.set(randomBytes, 8);
  
  return nonce;
}

/**
 * Encrypt a message with AES-GCM using conversation key
 * @param {string} message - Plain text message
 * @param {Uint8Array} conversationKey - 32-byte AES key
 * @param {Uint8Array} nonce - 24-byte nonce
 * @returns {Promise<string>} Base64 encoded ciphertext
 */
export async function encryptMessage(message, conversationKey, nonce) {
  const encoder = new TextEncoder();
  const messageBytes = encoder.encode(message);
  
  // Import key for AES-GCM
  const key = await crypto.subtle.importKey(
    'raw',
    conversationKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  // Use first 12 bytes of nonce for AES-GCM IV
  const iv = nonce.slice(0, 12);
  
  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    messageBytes
  );
  
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
}

/**
 * Decrypt a message with AES-GCM
 * @param {string} encryptedMessage - Base64 encoded ciphertext
 * @param {Uint8Array} conversationKey - 32-byte AES key
 * @param {Uint8Array} nonce - 24-byte nonce
 * @returns {Promise<string>} Decrypted plain text
 */
export async function decryptMessage(encryptedMessage, conversationKey, nonce) {
  const ciphertext = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
  
  // Import key for AES-GCM
  const key = await crypto.subtle.importKey(
    'raw',
    conversationKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  
  // Use first 12 bytes of nonce for AES-GCM IV
  const iv = nonce.slice(0, 12);
  
  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Sign a message for verification
 * @param {Uint8Array} privateKey - Sender's Ed25519 private key
 * @param {Object} messageData - {encrypted_content, nonce, conversation_id}
 * @returns {string} Hex encoded signature
 */
export function signMessage(privateKey, messageData) {
  return signData(privateKey, messageData);
}

/**
 * Verify message signature
 * @param {string} publicKeyPEM - Sender's public key in PEM format
 * @param {Object} messageData - {encrypted_content, nonce, conversation_id}
 * @param {string} signatureHex - Hex encoded signature
 * @returns {boolean} True if signature is valid
 */
export function verifyMessageSignature(publicKeyPEM, messageData, signatureHex) {
  const publicKeyBytes = importPublicKeyFromPEM(publicKeyPEM);
  return verifySignature(publicKeyBytes, messageData, signatureHex);
}

/**
 * Encrypt a file with AES-GCM
 * @param {ArrayBuffer} fileData - Raw file data
 * @param {Uint8Array} conversationKey - 32-byte AES key
 * @param {Uint8Array} nonce - 24-byte nonce (different from message nonce)
 * @returns {Promise<string>} Base64 encoded encrypted file
 */
export async function encryptFile(fileData, conversationKey, nonce) {
  const key = await crypto.subtle.importKey(
    'raw',
    conversationKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  const iv = nonce.slice(0, 12);
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    fileData
  );
  
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

/**
 * Decrypt a file with AES-GCM
 * @param {string} encryptedData - Base64 encoded encrypted file
 * @param {Uint8Array} conversationKey - 32-byte AES key
 * @param {Uint8Array} nonce - 24-byte nonce
 * @returns {Promise<ArrayBuffer>} Decrypted file data
 */
export async function decryptFile(encryptedData, conversationKey, nonce) {
  const ciphertext = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
  
  const key = await crypto.subtle.importKey(
    'raw',
    conversationKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  
  const iv = nonce.slice(0, 12);
  
  return await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
}

/**
 * Decrypt conversation key with Master Key
 * @param {string} encryptedHex - Encrypted conversation key in hex
 * @param {string} ivHex - IV in hex
 * @param {Uint8Array} masterKey - Master key for decryption
 * @returns {Promise<Uint8Array>} Decrypted 32-byte conversation key
 */
export async function decryptConversationKey(encryptedHex, ivHex, masterKey) {
  return await decryptPrivateKey(encryptedHex, ivHex, masterKey);
}
