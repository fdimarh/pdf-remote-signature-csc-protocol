#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Initialize SoftHSM v2 token with Nowina DSS test certificates
# ═══════════════════════════════════════════════════════════════
#
# Creates a PKCS#11 token and imports:
#   - Private key (RSA 3072-bit from Nowina DSS PKI Factory)
#   - User certificate (CN=good-user-crl-ocsp)
#   - CA chain certificates (good-ca + root-ca)
#
# Token: label="signing", slot=0
# PIN: 1234, SO-PIN: 5678
# Key label: "user-key", ID: 01
# Cert labels: "user-cert" (ID: 01), "ca-cert-N" (ID: 02+)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

CERT_DIR="/opt/certs"
PKCS11_LIB="/usr/lib/softhsm/libsofthsm2.so"
TOKEN_LABEL="signing"
PIN="1234"
SO_PIN="5678"
KEY_LABEL="user-key"
CERT_LABEL="user-cert"

echo "=== SoftHSM v2 Token Initialization ==="
echo ""

# ── Step 1: Initialize the token ──
echo "[1/5] Initializing SoftHSM token (label=$TOKEN_LABEL)..."
softhsm2-util --init-token --slot 0 \
    --label "$TOKEN_LABEL" \
    --pin "$PIN" \
    --so-pin "$SO_PIN"

echo "  Token initialized."

# ── Step 2: Convert PKCS#8 PEM private key to DER ──
echo "[2/5] Converting private key to DER format..."
openssl pkey -in "$CERT_DIR/user-key.pem" -outform DER -out /tmp/user-key.der
echo "  Key converted: $(wc -c < /tmp/user-key.der) bytes"

# ── Step 3: Import private key into HSM ──
echo "[3/5] Importing private key into token (label=$KEY_LABEL, id=01)..."
pkcs11-tool --module "$PKCS11_LIB" \
    --login --pin "$PIN" \
    --token-label "$TOKEN_LABEL" \
    --write-object /tmp/user-key.der \
    --type privkey \
    --label "$KEY_LABEL" \
    --id 01
echo "  Private key imported."

# ── Step 4: Import user certificate into HSM ──
echo "[4/5] Importing user certificate (label=$CERT_LABEL, id=01)..."
openssl x509 -in "$CERT_DIR/user-cert.pem" -outform DER -out /tmp/user-cert.der
pkcs11-tool --module "$PKCS11_LIB" \
    --login --pin "$PIN" \
    --token-label "$TOKEN_LABEL" \
    --write-object /tmp/user-cert.der \
    --type cert \
    --label "$CERT_LABEL" \
    --id 01
echo "  User certificate imported."

# ── Step 5: Import CA chain certificates into HSM ──
echo "[5/5] Importing CA chain certificates..."
# Split the PEM chain into individual certificates using awk
awk 'BEGIN {n=0} /-----BEGIN CERTIFICATE-----/{n++; fn=sprintf("/tmp/ca-cert-%02d.pem", n)} {if(n>0) print > fn}' "$CERT_DIR/ca-chain.pem"

CA_IDX=0
for pem_file in /tmp/ca-cert-*.pem; do
    # Skip if no files matched
    [ -f "$pem_file" ] || continue
    # Check if it actually contains a certificate
    grep -q "BEGIN CERTIFICATE" "$pem_file" || continue

    CA_IDX=$((CA_IDX + 1))
    CERT_ID=$(printf "%02x" $((CA_IDX + 1)))
    CA_LABEL="ca-cert-${CA_IDX}"

    openssl x509 -in "$pem_file" -outform DER -out "/tmp/${CA_LABEL}.der"
    SUBJECT=$(openssl x509 -in "$pem_file" -noout -subject 2>/dev/null || echo "unknown")

    pkcs11-tool --module "$PKCS11_LIB" \
        --login --pin "$PIN" \
        --token-label "$TOKEN_LABEL" \
        --write-object "/tmp/${CA_LABEL}.der" \
        --type cert \
        --label "$CA_LABEL" \
        --id "$CERT_ID"

    echo "  CA[$CA_IDX]: $SUBJECT (label=$CA_LABEL, id=$CERT_ID)"
done

echo ""
echo "=== Token initialization complete ==="
echo ""

# ── Verify: list all objects in the token ──
echo "--- Token contents ---"
pkcs11-tool --module "$PKCS11_LIB" \
    --login --pin "$PIN" \
    --token-label "$TOKEN_LABEL" \
    --list-objects 2>/dev/null || echo "(list failed)"

echo ""
echo "--- Token slots ---"
softhsm2-util --show-slots

# Clean up temp files
rm -f /tmp/user-key.der /tmp/user-cert.der /tmp/ca-cert-*.pem /tmp/ca-cert-*.der

echo ""
echo "✅ SoftHSM v2 ready."
echo "   PKCS#11 lib: $PKCS11_LIB"
echo "   Token:       $TOKEN_LABEL (PIN: $PIN)"
echo "   Key:         $KEY_LABEL (id: 01)"
echo "   Cert:        $CERT_LABEL (id: 01)"
echo "   CA certs:    $CA_IDX imported"

