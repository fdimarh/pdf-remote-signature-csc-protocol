# SoftHSM v2 — Operations & Troubleshooting Guide

> **Purpose**: This guide covers how to operate, manage, and troubleshoot the SoftHSM v2 PKCS#11 backend used by the Remote Signature PDF signing server.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Token Management](#token-management)
5. [Adding a New User Certificate](#adding-a-new-user-certificate)
6. [Replacing an Existing Certificate](#replacing-an-existing-certificate)
7. [Common Operations](#common-operations)
8. [Server CLI Reference](#server-cli-reference)
9. [Troubleshooting](#troubleshooting)
10. [Security Notes](#security-notes)

---

## Overview

SoftHSM v2 is a software-based PKCS#11 cryptographic token used as a **development/prototype** replacement for hardware HSMs (e.g., Thales Luna, AWS CloudHSM). It stores private keys in an encrypted token file and exposes them via the standard PKCS#11 interface.

**Key principle**: The private key never leaves the HSM boundary. The signing server sends data to the HSM via PKCS#11, and the HSM returns the signature. The key material is never loaded into application memory.

### Default Configuration

| Parameter       | Value                                  |
|-----------------|----------------------------------------|
| Token label     | `signing`                              |
| User PIN        | `1234`                                 |
| SO (Admin) PIN  | `5678`                                 |
| Key label       | `user-key`                             |
| Key ID          | `01`                                   |
| Cert label      | `user-cert`                            |
| Cert ID         | `01`                                   |
| PKCS#11 library | `/usr/lib/softhsm/libsofthsm2.so`     |
| Token directory | `/var/lib/softhsm/tokens`              |
| Config file     | `/etc/softhsm2.conf`                   |

---

## Quick Start

### Start with Docker Compose (recommended)

```bash
# Build and start SoftHSM + signing server
docker compose up --build -d

# Check both services are running
docker compose ps

# Expected output:
#   softhsm-signing   ... (healthy)
#   signing-server     ... Up
```

### Verify HSM is ready

```bash
# Check SoftHSM token initialization
docker logs softhsm-signing 2>&1 | tail -10

# Expected:
#   ✅ SoftHSM v2 ready.
#      Token: signing (PIN: 1234)
#      Key:   user-key (id: 01)
#      Cert:  user-cert (id: 01)
#      CA certs: 2 imported
```

### Verify server is using HSM backend

```bash
# Check server startup logs
docker logs signing-server 2>&1 | grep -E "PKI|PKCS|HSM"

# Expected:
#   PKCS#11 token: label='signing', model='SoftHSM v2'
#   PKCS#11 session authenticated (User)
#   Found private key: label='user-key'
#   HSM backend initialized: key='user-key' via PKCS#11
#   Using PKI backend: HSM (PKCS#11)
```

### Quick signing test

```bash
# Authenticate
TOKEN=$(curl -s -u testuser:testpass -X POST \
  http://localhost:8080/csc/v2/auth/login \
  -H "Content-Type: application/json" -d '{}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Sign a hash via HSM
curl -s -X POST http://localhost:8080/csc/v2/signatures/signHash \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "credentialID": "credential-001",
    "hashes": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
    "hashAlgo": "2.16.840.1.101.3.4.2.1",
    "signAlgo": "1.2.840.113549.1.1.11",
    "signatureFormat": "pades",
    "padesLevel": "B-B"
  }' | python3 -m json.tool

# If successful, you'll see a "signatures" array with a Base64 CMS blob
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Compose                                     │
│                                                     │
│  ┌──────────────┐     ┌──────────────────────────┐  │
│  │  softhsm     │     │  server                  │  │
│  │  (Alpine)    │     │  (Debian bookworm-slim)  │  │
│  │              │     │                          │  │
│  │  SoftHSM v2  │     │  Rust binary             │  │
│  │  pkcs11-tool │     │  + libsofthsm2.so        │  │
│  │  openssl     │     │                          │  │
│  └──────┬───────┘     └────────────┬─────────────┘  │
│         │                          │                │
│         └──────────┬───────────────┘                │
│                    │                                │
│         ┌──────────▼──────────┐                     │
│         │  Docker Volume      │                     │
│         │  hsm-tokens         │                     │
│         │  /var/lib/softhsm/  │                     │
│         │    tokens/          │                     │
│         └─────────────────────┘                     │
└─────────────────────────────────────────────────────┘

Signing flow:
  1. Client → POST /api/v1/signPdf → signing-server
  2. Server builds CMS signed-attributes (DER)
  3. Server calls: PKCS#11 C_Sign(CKM_SHA256_RSA_PKCS, data)
  4. SoftHSM hashes + signs inside the token
  5. Server receives RSA signature bytes
  6. Server assembles complete CMS/PKCS#7 SignedData
  7. Server embeds CMS into PDF → returns signed PDF
```

**File layout:**

```
docker/
├── softhsm/
│   ├── Dockerfile         # Alpine + SoftHSM2 + OpenSC + openssl
│   ├── init-hsm.sh        # Token init + key/cert import script
│   └── softhsm2.conf      # Token directory config
└── server/
    └── Dockerfile          # Rust server (Debian glibc, --features hsm)

docker-compose.yml          # Orchestrates both services
```

---

## Token Management

### List all tokens (slots)

```bash
docker exec softhsm-signing softhsm2-util --show-slots
```

### List all objects in a token

```bash
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label signing \
  --list-objects
```

Expected output:
```
Private Key Object; RSA
  label:      user-key
  ID:         01
  Usage:      sign
Certificate Object; type = X.509 cert
  label:      user-cert
  subject:    CN=good-user-crl-ocsp, ...
  ID:         01
Certificate Object; type = X.509 cert
  label:      ca-cert-1
  subject:    CN=good-ca, ...
  ID:         02
Certificate Object; type = X.509 cert
  label:      ca-cert-2
  subject:    CN=root-ca, ...
  ID:         03
```

### Delete a specific object

```bash
# Delete by label and type
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label signing \
  --delete-object --type privkey --label user-key
```

### Delete and reinitialize entire token

```bash
# Delete the token
docker exec softhsm-signing softhsm2-util --delete-token --token signing

# Reinitialize (runs the init script)
docker exec softhsm-signing /opt/init-hsm.sh
```

### Change User PIN

```bash
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label signing \
  --change-pin --new-pin 9999
```

> **Remember**: Update `--hsm-pin` in docker-compose.yml after changing the PIN.

---

## Adding a New User Certificate

This section explains how to import your own certificate and private key into the HSM for signing.

### Prerequisites

You need:
- **Private key** in PEM format (PKCS#8 or traditional RSA)
- **User certificate** in PEM format (X.509)
- **CA chain** in PEM format (intermediate + root, concatenated)

### Method 1: Replace files and rebuild (simplest)

```bash
# 1. Place your certificate files in certs/nowina/ (or a custom directory)
cp your-key.pem    certs/nowina/user-key.pem
cp your-cert.pem   certs/nowina/user-cert.pem
cp your-chain.pem  certs/nowina/ca-chain.pem

# 2. Remove old token data and rebuild
docker compose down
docker volume rm remote-signature-pdf_hsm-tokens
docker compose up --build -d

# 3. Verify
docker logs softhsm-signing 2>&1 | grep -E "imported|ready"
```

### Method 2: Import into running container (no rebuild)

```bash
# 1. Copy your cert files into the container
docker cp your-key.pem  softhsm-signing:/tmp/new-key.pem
docker cp your-cert.pem softhsm-signing:/tmp/new-cert.pem

# 2. Convert PEM to DER
docker exec softhsm-signing openssl pkey \
  -in /tmp/new-key.pem -outform DER -out /tmp/new-key.der

docker exec softhsm-signing openssl x509 \
  -in /tmp/new-cert.pem -outform DER -out /tmp/new-cert.der

# 3. Import private key (use a unique label and ID)
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label signing \
  --write-object /tmp/new-key.der \
  --type privkey \
  --label "new-user-key" \
  --id 10

# 4. Import certificate (same ID as the key to link them)
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label signing \
  --write-object /tmp/new-cert.der \
  --type cert \
  --label "new-user-cert" \
  --id 10

# 5. Verify the new objects appear
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label signing \
  --list-objects

# 6. To use the new key, restart the server with the new label:
#    Change --hsm-key-label in docker-compose.yml to "new-user-key"
#    Also update --cert-dir to point to the new cert PEM files
docker compose restart server
```

### Method 3: Import from a PKCS#12 (.p12 / .pfx) file

If you have a `.p12` file (e.g., from a CA or certificate authority):

```bash
# 1. Copy the .p12 file into the container
docker cp your-cert.p12 softhsm-signing:/tmp/cert.p12

# 2. Extract private key
docker exec softhsm-signing openssl pkcs12 \
  -in /tmp/cert.p12 -nocerts -nodes \
  -passin pass:your-p12-password \
  -out /tmp/extracted-key.pem

# 3. Extract user certificate
docker exec softhsm-signing openssl pkcs12 \
  -in /tmp/cert.p12 -clcerts -nokeys \
  -passin pass:your-p12-password \
  -out /tmp/extracted-cert.pem

# 4. Extract CA chain (if present)
docker exec softhsm-signing openssl pkcs12 \
  -in /tmp/cert.p12 -cacerts -nokeys \
  -passin pass:your-p12-password \
  -out /tmp/extracted-chain.pem

# 5. Convert to DER
docker exec softhsm-signing openssl pkey \
  -in /tmp/extracted-key.pem -outform DER -out /tmp/extracted-key.der

docker exec softhsm-signing openssl x509 \
  -in /tmp/extracted-cert.pem -outform DER -out /tmp/extracted-cert.der

# 6. Import into HSM
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --write-object /tmp/extracted-key.der \
  --type privkey --label "my-key" --id 20

docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --write-object /tmp/extracted-cert.der \
  --type cert --label "my-cert" --id 20

# 7. Verify
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --list-objects

# 8. Clean up sensitive files
docker exec softhsm-signing rm -f /tmp/cert.p12 /tmp/extracted-*.pem /tmp/extracted-*.der
```

### Important: Update the server cert directory

The signing server also reads **public** certificate PEM files from `--cert-dir` for:
- CSC `credentials/info` endpoint (returns cert chain to clients)
- Building the CMS certificate chain in signatures

After importing a new key into the HSM, you must also update the PEM files:

```bash
# Place the new cert + chain PEM files
mkdir -p certs/my-certs
cp your-cert.pem   certs/my-certs/user-cert.pem
cp your-key.pem    certs/my-certs/user-key.pem   # needed for PEM fallback
cp your-chain.pem  certs/my-certs/ca-chain.pem

# Update docker-compose.yml volumes:
#   - ./certs/my-certs:/opt/certs:ro
# Update server command:
#   --cert-dir /opt/certs
#   --hsm-key-label my-key
```

---

## Replacing an Existing Certificate

When a certificate expires or you need to rotate keys:

```bash
# 1. Delete old objects
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --delete-object --type privkey --label user-key

docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --delete-object --type cert --label user-cert

# 2. Import new key and cert (same labels and IDs)
# ... follow the import steps from "Method 2" above,
#     using --label "user-key" --id 01 and --label "user-cert" --id 01

# 3. Update the PEM files in certs/nowina/ for the server

# 4. Restart the server
docker compose restart server
```

---

## Common Operations

### Start / Stop / Restart

```bash
# Start everything
docker compose up -d

# Stop everything (preserves token data in volume)
docker compose down

# Stop and delete token data (full reset)
docker compose down -v

# Restart only the server (after config changes)
docker compose restart server

# Rebuild after code or cert changes
docker compose up --build -d
```

### View logs

```bash
# SoftHSM container (token init)
docker logs softhsm-signing

# Signing server (requests + HSM operations)
docker logs -f signing-server

# Filter for HSM-related messages
docker logs signing-server 2>&1 | grep -i -E "hsm|pkcs|backend|sign"
```

### Test a signing operation

```bash
# Run the full HSM test suite
bash test-files/test_hsm_signing.sh
```

### Check certificate details in the HSM

```bash
# Read a certificate from the token and display its details
docker exec softhsm-signing sh -c '
  pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label signing \
    --read-object --type cert --label user-cert \
    --output-file /tmp/read-cert.der && \
  openssl x509 -in /tmp/read-cert.der -inform DER -noout \
    -subject -issuer -dates -serial
'
```

### Verify key-certificate pairing

```bash
# The key ID and cert ID should match (both 01 for the default pair)
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --list-objects 2>&1 | grep -E "label:|ID:"
```

---

## Server CLI Reference

```bash
# PEM mode (default — no HSM needed)
cargo run -- server --port 8080

# HSM mode (requires --features hsm at build time)
cargo run --features hsm -- server \
  --port 8080 \
  --pki-backend hsm \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --hsm-slot 0 \
  --hsm-pin 1234 \
  --hsm-key-label user-key \
  --cert-dir ./certs/nowina
```

| Flag              | Description                                    | Default               |
|-------------------|------------------------------------------------|-----------------------|
| `--pki-backend`   | `pem` (file-based) or `hsm` (PKCS#11)         | `pem`                 |
| `--pkcs11-lib`    | Path to PKCS#11 `.so` shared library           | *(required for hsm)*  |
| `--hsm-slot`      | Token slot index                               | `0`                   |
| `--hsm-pin`       | User PIN for the token                         | *(required for hsm)*  |
| `--hsm-key-label` | Label of the private key in the token          | `user-key`            |
| `--cert-dir`      | Directory with PEM cert files (public data)    | `./certs/nowina`      |

---

## Troubleshooting

### Problem: "Dynamic loading not supported"

```
Failed to load PKCS#11 library: /usr/lib/softhsm/libsofthsm2.so
Caused by: libloading error (Dynamic loading not supported)
```

**Cause**: The binary was compiled with musl (Alpine) which doesn't support `dlopen`.

**Fix**: The server must be compiled with glibc (Debian/Ubuntu). The `docker/server/Dockerfile` uses `rust:1-bookworm` + `debian:bookworm-slim` for this reason. If building locally on macOS, this isn't an issue (macOS uses dynamic linking by default).

---

### Problem: "No initialized PKCS#11 tokens found"

```
No initialized PKCS#11 tokens found
```

**Cause**: The SoftHSM token directory is empty — the init script hasn't run, or the Docker volume wasn't mounted.

**Fix**:
```bash
# Check if softhsm container started and initialized
docker logs softhsm-signing 2>&1 | grep -E "ready|Error"

# Check the shared volume has files
docker exec softhsm-signing ls -la /var/lib/softhsm/tokens/

# Reinitialize if needed
docker exec softhsm-signing /opt/init-hsm.sh

# Or full reset
docker compose down -v && docker compose up --build -d
```

---

### Problem: "Private key with label 'xxx' not found"

```
Private key with label 'user-key' not found in PKCS#11 token
```

**Cause**: The key wasn't imported, or was imported with a different label.

**Fix**:
```bash
# List all objects to see what's actually there
docker exec softhsm-signing pkcs11-tool \
  --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 --token-label signing \
  --list-objects

# If the key is missing, re-import it:
docker exec softhsm-signing /opt/init-hsm.sh

# If the label is different, update --hsm-key-label in docker-compose.yml
```

---

### Problem: "Failed to login to PKCS#11 token"

```
Failed to login to PKCS#11 token
CKR_PIN_INCORRECT
```

**Cause**: Wrong PIN.

**Fix**: The default PIN is `1234`. If it was changed, update `--hsm-pin` in docker-compose.yml. If locked out:
```bash
# Reset the token entirely (destroys all objects)
docker exec softhsm-signing softhsm2-util --delete-token --token signing
docker exec softhsm-signing /opt/init-hsm.sh
```

---

### Problem: "PKCS#11 RSA-SHA256 signing failed"

```
PKCS#11 RSA-SHA256 signing failed
CKR_KEY_HANDLE_INVALID
```

**Cause**: The session or key handle became stale (rare, usually after token reinit without server restart).

**Fix**:
```bash
docker compose restart server
```

---

### Problem: "HSM backend detected — routing signDoc through hash-based CMS builder"

This is **not an error** — it's the expected INFO log. When the HSM backend is active, the server routes signing through the hash-based CMS path because the private key is not extractable from the HSM. The library-based `SignedDataBuilder` requires an in-memory key, so the server instead:

1. Computes the SHA-256 hash of the content
2. Builds the CMS signed attributes manually
3. Calls PKCS#11 `C_Sign(CKM_SHA256_RSA_PKCS)` to sign the attributes
4. Assembles the final CMS SignedData structure

---

### Problem: Server is slow to start with HSM

**Cause**: The server waits for the `softhsm` container healthcheck before starting. The healthcheck runs every 3 seconds with 10 retries (max ~30s).

**Fix**: This is normal. Check with:
```bash
docker compose ps   # softhsm should show (healthy)
```

---

### Problem: Docker build takes very long (10+ minutes)

**Cause**: The Rust release compilation inside Docker builds ~400 crate dependencies from scratch.

**Workarounds**:
- Use `docker compose build` (not `--no-cache`) to reuse layers
- For development, build locally: `cargo build --features hsm`
- Consider using `cargo-chef` for Docker layer caching (advanced)

---

### Problem: Certificate mismatch between HSM and PEM files

```
CMS signature verification failed: digest mismatch
```

**Cause**: The private key in the HSM doesn't match the certificate in `--cert-dir`. They must be a matching key pair.

**Verify**:
```bash
# Get the public key modulus from the HSM cert
docker exec softhsm-signing sh -c '
  pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label signing \
    --read-object --type cert --label user-cert -o /tmp/c.der && \
  openssl x509 -in /tmp/c.der -inform DER -noout -modulus | md5sum
'

# Get the public key modulus from the PEM cert file
openssl x509 -in certs/nowina/user-cert.pem -noout -modulus | md5sum

# Both md5sums should be identical
```

---

### Problem: "Token 'signing' already exists — skipping initialization"

This is **not an error**. The init script is idempotent — if the token already exists in the shared volume, it skips re-initialization to avoid duplicate objects.

To force re-initialization:
```bash
docker compose down -v       # delete the volume
docker compose up --build -d  # recreate from scratch
```

---

## Security Notes

> ⚠️ **This is a development/prototype setup. Do NOT use in production as-is.**

| Concern | Current State | Production Recommendation |
|---------|---------------|---------------------------|
| PIN storage | Hardcoded in docker-compose.yml | Use Docker secrets or env vars from vault |
| Token encryption | SoftHSM file-based (AES) | Hardware HSM (FIPS 140-2 Level 3+) |
| Key extractability | SoftHSM allows key export | Hardware HSMs enforce non-extractable |
| Network exposure | Port 8080, no TLS | TLS termination (nginx/traefik) |
| Auth tokens | Simple JWT, no rotation | OAuth2 / mTLS for production |
| SO-PIN | Hardcoded `5678` | Generate randomly, store securely |
| Audit logging | Server logs only | SIEM integration, HSM audit trail |

### Migrating to a hardware HSM

The PKCS#11 interface is standard. To switch from SoftHSM to a hardware HSM:

1. Install the vendor's PKCS#11 library (`.so` file)
2. Import your key and certificates into the hardware token
3. Update `--pkcs11-lib` to point to the vendor library
4. Update `--hsm-slot`, `--hsm-pin`, `--hsm-key-label` as needed
5. No code changes required — the `cryptoki` crate works with any PKCS#11 provider

---

*Last updated: 2026-03-09*

