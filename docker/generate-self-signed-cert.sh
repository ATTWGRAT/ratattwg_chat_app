#!/bin/bash
# Generate self-signed SSL certificates for testing
# DO NOT use these certificates in production!

CERT_DIR="./docker/ssl"
mkdir -p "$CERT_DIR"

# Generate private key and certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Set proper permissions
chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo "Self-signed certificate generated successfully!"
echo "Certificate: $CERT_DIR/cert.pem"
echo "Private Key: $CERT_DIR/key.pem"
echo ""
echo "WARNING: This is a self-signed certificate for testing only!"
echo "For production, use certificates from a trusted CA like Let's Encrypt."
