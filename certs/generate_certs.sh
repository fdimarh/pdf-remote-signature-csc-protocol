#!/bin/bash
# Generate test certificates for CSC Remote Signing Prototype
# Creates a self-signed CA and a user certificate signed by the CA

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating Test Certificates ==="

# --- CA Certificate ---
echo "[1/4] Generating CA private key..."
openssl genrsa -out ca-key.pem 2048

echo "[2/4] Generating CA self-signed certificate..."
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 \
  -subj "/C=ID/ST=Jakarta/L=Jakarta/O=CSC Prototype CA/OU=PKI/CN=CSC Prototype Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- User/Signer Certificate ---
echo "[3/4] Generating user private key and CSR..."
openssl genrsa -out user-key.pem 2048

openssl req -new -key user-key.pem -out user.csr \
  -subj "/C=ID/ST=Jakarta/L=Jakarta/O=CSC Prototype/OU=Signing/CN=Test Signer/emailAddress=signer@example.com"

echo "[4/4] Signing user certificate with CA..."
openssl x509 -req -in user.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out user-cert.pem -days 1825 \
  -extfile <(cat <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
)

# Cleanup CSR
rm -f user.csr ca-cert.srl

echo ""
echo "=== Certificates Generated ==="
echo "  CA Certificate:   $SCRIPT_DIR/ca-cert.pem"
echo "  CA Private Key:   $SCRIPT_DIR/ca-key.pem"
echo "  User Certificate: $SCRIPT_DIR/user-cert.pem"
echo "  User Private Key: $SCRIPT_DIR/user-key.pem"
echo ""

# Print certificate info
echo "--- CA Certificate Info ---"
openssl x509 -in ca-cert.pem -noout -subject -issuer -dates
echo ""
echo "--- User Certificate Info ---"
openssl x509 -in user-cert.pem -noout -subject -issuer -dates

