# Remote Signature PDF — CSC Protocol Prototype

## Overview

A **client-server** remote PDF signing system based on the **Cloud Signature Consortium (CSC) API v2** specification. The server acts as a **PKI / Trust Service Provider (TSP)**, managing certificates and performing cryptographic signing operations. The client handles **PDF preparation** (hash computation, placeholder insertion, signature embedding).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT                                │
│                                                              │
│  1. Load PDF                                                 │
│  2. Insert signature placeholder (ByteRange + Contents)      │
│  3. Extract byte-range content (PDF minus placeholder)       │
│  4. Call server /signatures/signDoc (⭐ recommended)         │
│     — or /signatures/signHash (simplified)                   │
│  5. Receive CMS/PKCS#7 signature blob                       │
│  6. Embed signature into Contents field                      │
│  7. Output signed PDF                                        │
│                                                              │
│  8. [Optional] Call /api/v1/validate to verify the result    │
└──────────────┬───────────────────────────────────────────────┘
               │  REST API (CSC v2 protocol)
               ▼
┌─────────────────────────────────────────────────────────────┐
│                        SERVER                                │
│                                                              │
│  /csc/v2/info              — Service information             │
│  /csc/v2/auth/login        — Authenticate user (get token)   │
│  /csc/v2/credentials/list  — List user's signing credentials │
│  /csc/v2/credentials/info  — Get certificate chain details   │
│  /csc/v2/signatures/signHash — Sign a hash (simplified)      │
│  /csc/v2/signatures/signDoc  — Sign content (⭐ recommended) │
│  /csc/v2/signatures/signDoc/form — Sign content (file upload)│
│  /api/v1/signPdf             — Full server-side signing ⭐⭐   │
│  /api/v1/signPdf/form        — Full signing (file upload)    │
│  /api/v1/validate          — Validate signed PDF             │
│  /api/v1/validate/form     — Validate (file upload)          │
│                                                              │
│  Signing Formats:                                            │
│    • PKCS#7 (adbe.pkcs7.detached) + LTV (CRL/OCSP)         │
│    • PAdES  (ETSI.CAdES.detached)                           │
│                                                              │
│  PAdES Levels: B-B, B-T, B-LT (DSS), B-LTA (doc timestamp) │
│                                                              │
│  LTV Pipeline (server/ltv.rs):                               │
│    • CRL/OCSP fetching from cert extensions                  │
│    • adbe-revocationInfoArchival CMS attribute               │
│    • DSS dictionary appending                                │
│    • RFC 3161 document timestamp (B-LTA)                     │
│                                                              │
│  PKI Backend:                                                │
│    • X.509 certificate chain + private key (PEM files)       │
│    • Supports multi-level chains (e.g., Nowina 3-level PKI) │
│    • CMS/PKCS#7 SignedData builder                           │
│    • ESS-signing-certificate-v2 attribute                    │
│    • Optional: TSA timestamp, CRL/OCSP revocation data       │
└─────────────────────────────────────────────────────────────┘
```

---

## CSC API Endpoints (Subset for Prototype)

Based on [CSC API v2.0 spec](https://cloudsignatureconsortium.org/resources/download-api-specifications/):

### 1. `POST /csc/v2/info`
Service metadata (name, supported algorithms, etc.)

**Response:**
```json
{
  "specs": "2.0.0.0",
  "name": "Remote Signature PDF Prototype",
  "logo": "",
  "region": "ID",
  "lang": "en",
  "description": "CSC v2 prototype signing service",
  "authType": ["basic"],
  "methods": [
    "auth/login",
    "credentials/list",
    "credentials/info",
    "signatures/signHash",
    "signatures/signDoc",
    "signPdf",
    "validate"
  ],
  "signatureFormats": ["pkcs7", "pades"],
  "padesLevels": ["B-B", "B-T", "B-LT", "B-LTA"]
}
```

### 2. `POST /csc/v2/auth/login`
Simple token-based authentication (static users for prototype).

**Request:**
```json
{
  "rememberMe": true
}
```
+ Basic Auth header

**Response:**
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 3. `POST /csc/v2/credentials/list`
List available signing credentials for the authenticated user.

**Response:**
```json
{
  "credentialIDs": ["credential-001"]
}
```

### 4. `POST /csc/v2/credentials/info`
Get certificate chain and key info for a credential.

**Request:**
```json
{
  "credentialID": "credential-001",
  "certificates": "chain"
}
```

**Response:**
```json
{
  "key": {
    "status": "enabled",
    "algo": ["1.2.840.113549.1.1.11"],
    "len": 2048
  },
  "cert": {
    "status": "valid",
    "certificates": ["<base64-DER-cert>", "..."],
    "issuerDN": "CN=Test CA, O=Prototype",
    "serialNumber": "...",
    "subjectDN": "CN=Test User, O=Prototype",
    "validFrom": "2024-01-01T00:00:00Z",
    "validTo": "2027-01-01T00:00:00Z"
  },
  "authMode": "implicit"
}
```

### 5. `POST /csc/v2/signatures/signHash`

> **What it does:** The client computes the hash locally, then sends *only the hash* to the server. The server wraps that hash into a CMS SignedData structure and returns it.

**How it works — step by step:**

```
 CLIENT                                   SERVER
   │                                        │
   │  1. Prepare PDF (insert placeholder)   │
   │  2. Compute SHA-256 of ByteRange       │
   │     → 32-byte hash                     │
   │                                        │
   │  3. POST /signatures/signHash          │
   │     { hashes: [base64(hash)] }         │
   ├───────────────────────────────────────→ │
   │                                        │  4. Decode the 32-byte hash
   │                                        │  5. Build CMS SignedData with
   │                                        │     the hash as external content
   │                                        │  6. Sign with private key
   │  { signatures: [base64(cms)] }         │
   │ ←──────────────────────────────────────┤
   │                                        │
   │  7. Embed CMS into PDF Contents field  │
```

**When to use:**
- Standard CSC v2 protocol compliance
- When the client handles all hash computation
- Batch signing (multiple hashes in one call)

**Limitation:** The server treats the received hash as raw external content, so the CMS `messageDigest` attribute will contain `SHA256(hash)` instead of `SHA256(original_pdf_bytes)`. This is a **simplified** implementation. For correct PDF signatures, use `signDoc` instead.

**Request:**
```json
{
  "credentialID": "credential-001",
  "SAD": "...",
  "hashes": ["<base64-encoded-SHA256-hash>"],
  "hashAlgo": "2.16.840.1.101.3.4.2.1",
  "signAlgo": "1.2.840.113549.1.1.11"
}
```

**Response:**
```json
{
  "signatures": ["<base64-encoded-CMS-SignedData>"]
}
```

**Error responses:**
| HTTP | Error | Cause |
|------|-------|-------|
| 400 | `invalid_request` | Empty hashes array, wrong hash length (must be 32 bytes), unsupported algorithm, invalid Base64 |
| 401 | `invalid_token` | Missing or expired Bearer token |
| 403 | `invalid_request` | Credential ID not accessible by this user |

---

### 6. `POST /csc/v2/signatures/signDoc` ⭐ Recommended

> **What it does:** The client sends the *raw PDF byte-range content* (everything except the signature placeholder) to the server. The server computes the hash internally, builds the CMS SignedData with the correct `messageDigest`, and returns it. This produces **cryptographically correct** PDF signatures.

**How it works — step by step:**

```
 CLIENT                                   SERVER
   │                                        │
   │  1. Prepare PDF (insert placeholder)   │
   │  2. Extract byte-range content         │
   │     (PDF bytes minus the <hex>         │
   │      Contents placeholder)             │
   │                                        │
   │  3. POST /signatures/signDoc           │
   │     { documentContent: base64(bytes),  │
   │       signatureFormat: "pades",        │
   │       padesLevel: "B-B" }              │
   ├───────────────────────────────────────→ │
   │                                        │  4. Decode the content bytes
   │                                        │  5. Compute SHA-256 internally
   │                                        │  6. Build CMS SignedData:
   │                                        │     • messageDigest = SHA256(content)
   │                                        │     • ESS-signing-certificate-v2
   │                                        │     • Signer certificate chain
   │                                        │     • [Optional] Timestamp (TSA)
   │                                        │  7. Sign with private key
   │  { signature: base64(cms),             │
   │    signatureFormat: "pades",           │
   │    padesLevel: "B-B" }                 │
   │ ←──────────────────────────────────────┤
   │                                        │
   │  8. Embed CMS into PDF Contents field  │
```

**When to use:**
- **Always recommended** for PDF signing — produces valid signatures
- Supports all signature formats and PAdES conformance levels
- The server has full control over the CMS structure

**Request:**
```json
{
  "credentialID": "credential-001",
  "documentContent": "<base64-encoded-byte-range-content>",
  "hashAlgo": "2.16.840.1.101.3.4.2.1",
  "signAlgo": "1.2.840.113549.1.1.11",
  "signatureFormat": "pades",
  "padesLevel": "B-B",
  "timestampUrl": "http://timestamp.digicert.com",
  "includeCrl": false,
  "includeOcsp": false
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `credentialID` | ✅ | — | The signing credential to use |
| `documentContent` | ✅ | — | Base64-encoded concatenated byte-range content |
| `hashAlgo` | ✅ | — | Must be `2.16.840.1.101.3.4.2.1` (SHA-256) |
| `signAlgo` | ✅ | — | Must be `1.2.840.113549.1.1.11` (RSA-SHA256) |
| `signatureFormat` | | `"pades"` | `"pkcs7"` or `"pades"` |
| `padesLevel` | | `"B-B"` | `"B-B"`, `"B-T"`, `"B-LT"`, `"B-LTA"` |
| `timestampUrl` | | — | TSA URL (required for B-T, B-LT, B-LTA) |
| `includeCrl` | | `false` | Embed CRL in CMS signed attributes |
| `includeOcsp` | | `false` | Embed OCSP in CMS signed attributes |

**Response:**
```json
{
  "signature": "<base64-encoded-CMS-SignedData>",
  "signatureFormat": "pades",
  "padesLevel": "B-B"
}
```

**Error responses:**
| HTTP | Error | Cause |
|------|-------|-------|
| 400 | `invalid_request` | Invalid Base64 content, unsupported hash algorithm |
| 401 | `invalid_token` | Missing or expired Bearer token |
| 403 | `invalid_request` | Credential ID not accessible by this user |
| 500 | `server_error` | CMS build failure (key/cert issue) |

**Supported signature formats and levels:**

| Format | SubFilter | Description |
|--------|-----------|-------------|
| `pkcs7` | `adbe.pkcs7.detached` | Adobe PKCS#7 detached signature |
| `pades` | `ETSI.CAdES.detached` | PAdES (European standard for advanced signatures) |

| PAdES Level | Timestamp | DSS | Description |
|-------------|-----------|-----|-------------|
| `B-B` | ❌ | ❌ | Basic — ESS-signing-certificate-v2 only |
| `B-T` | ✅ (TSA) | ❌ | Adds a signature timestamp proving when the signature was created |
| `B-LT` | ✅ (TSA) | ✅ | Adds DSS dictionary with CRL/OCSP for offline long-term validation |
| `B-LTA` | ✅ (TSA) | ✅ | Adds a document timestamp on top of B-LT for archival protection |

---

### signHash vs. signDoc — Which to Use?

```
┌─────────────────────────────────────────────────────────────────┐
│                    signHash (simplified)                         │
│                                                                 │
│  Client computes hash  →  sends 32 bytes  →  Server wraps CMS  │
│                                                                 │
│  ✓ Standard CSC v2 protocol                                    │
│  ✓ Minimal data transfer (32 bytes)                            │
│  ✗ CMS messageDigest = SHA256(hash), not SHA256(pdf_content)   │
│  ✗ PDF viewers may reject the signature                        │
│                                                                 │
│  Use for: non-PDF signing, testing, batch hash signing          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    signDoc (recommended) ⭐                      │
│                                                                 │
│  Client sends content  →  Server hashes + builds CMS properly  │
│                                                                 │
│  ✓ CMS messageDigest = SHA256(pdf_content) — correct!          │
│  ✓ Server controls full CMS structure                          │
│  ✓ Supports PKCS7, PAdES B-B / B-T / B-LT / B-LTA            │
│  ✓ PDF viewers accept and validate the signature               │
│  ✗ More data transfer (full byte-range content)                │
│                                                                 │
│  Use for: all PDF signing operations                            │
└─────────────────────────────────────────────────────────────────┘
```

---

### 7. `POST /api/v1/validate`

> **What it does:** Accepts a Base64-encoded signed PDF and returns comprehensive validation results for every digital signature in the document.

**Request:**
```json
{
  "pdfContent": "<base64-encoded-PDF-bytes>",
  "password": null
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `pdfContent` | ✅ | Base64-encoded PDF file bytes |
| `password` | | Password for encrypted PDFs (null if unencrypted) |

**Response:**
```json
{
  "signatureCount": 1,
  "allValid": true,
  "signatures": [
    {
      "fieldName": "Signature123",
      "signerName": "CN=Test Signer",
      "subFilter": "ETSI.CAdES.detached",
      "signingTime": "D:20260307...",
      "isValid": true,
      "digestMatch": true,
      "cmsSignatureValid": true,
      "certificateChainValid": true,
      "certificateChainTrusted": false,
      "byteRangeValid": true,
      "byteRangeCoversWholeFile": true,
      "hasTimestamp": false,
      "hasDss": false,
      "isLtvEnabled": false,
      "noUnauthorizedModifications": true,
      "signatureNotWrapped": true,
      "certificationPermissionOk": true,
      "isDocumentTimestamp": false,
      "isEncrypted": false,
      "certificates": [ ... ],
      "securityWarnings": [],
      "errors": []
    }
  ]
}
```

**Validation checks performed:**

| Check | Description | Defends Against |
|-------|-------------|-----------------|
| `digestMatch` | SHA-256 of byte-range matches CMS messageDigest | Tampering |
| `cmsSignatureValid` | RSA signature over signed attributes verifies | Forgery |
| `certificateChainValid` | Each cert signed by the next in chain, none expired | Impersonation |
| `byteRangeValid` | ByteRange starts at 0, no gaps, no overlaps | Universal Signature Forgery (USF) |
| `signatureNotWrapped` | Contents hex-string located exactly in ByteRange gap | Signature Wrapping Attack (SWA) |
| `certificationPermissionOk` | MDP permissions not violated by subsequent changes | PDF Certification Attack |
| `noUnauthorizedModifications` | No unauthorized incremental updates after signing | Post-sign tampering |
| `hasDss` / `isLtvEnabled` | DSS dictionary with CRL/OCSP for offline validation | Long-term verification |
| `hasTimestamp` | CMS contains a signature timestamp from a TSA | Proof of existence at time |

---

### 8. `POST /api/v1/signPdf` ⭐⭐ Full Server-Side Signing

> **What it does:** Accepts a complete PDF file + optional signature image, and performs the **entire signing pipeline server-side** — PDF preparation, visible image embedding, hash computation, CMS signing, and signature embedding — in a single HTTP call. The client just uploads and downloads.

**How it works — step by step:**

```
 CLIENT                                   SERVER
   │                                        │
   │  POST /api/v1/signPdf                  │
   │  { pdfContent: base64(pdf),            │
   │    imageContent: base64(png), ← opt.   │
   │    sigRect: [50,50,250,150],           │
   │    signatureFormat: "pades",           │
   │    padesLevel: "B-B" }                 │
   ├───────────────────────────────────────→ │
   │                                        │  1. Decode PDF + image bytes
   │                                        │  2. Insert signature placeholder
   │                                        │  3. [If image] Build visible
   │                                        │     appearance (Form XObject)
   │                                        │  4. Fix ByteRange
   │                                        │  5. Compute SHA-256 of ranges
   │                                        │  6. Build CMS SignedData
   │                                        │  7. Embed CMS into PDF
   │  { signedPdf: base64(signed_pdf),      │
   │    signatureFormat: "pades",           │
   │    padesLevel: "B-B",                  │
   │    hasVisibleSignature: true }         │
   │ ←──────────────────────────────────────┤
   │                                        │
   │  [Client saves signed PDF]             │
```

**When to use:**
- Simplest integration — one API call does everything
- When the client doesn't want to handle PDF manipulation
- Web/mobile apps that upload files for signing
- Server controls the entire signing pipeline (most secure)

**Request:**
```json
{
  "credentialID": "credential-001",
  "pdfContent": "<base64-encoded-PDF-file>",
  "imageContent": "<base64-encoded-PNG-or-JPEG>",
  "sigRect": [50, 50, 250, 150],
  "sigPage": 1,
  "signerName": "John Doe",
  "signatureFormat": "pades",
  "padesLevel": "B-B",
  "timestampUrl": null,
  "includeCrl": false,
  "includeOcsp": false
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `credentialID` | ✅ | — | Signing credential ID |
| `pdfContent` | ✅ | — | Base64-encoded PDF file |
| `imageContent` | | `null` | Base64-encoded PNG/JPEG for visible signature |
| `sigRect` | when image | — | `[x1, y1, x2, y2]` in PDF points |
| `sigPage` | | `1` | Target page (1-based) |
| `signerName` | | `"Digital Signature"` | Display name in the /Name field |
| `signatureFormat` | | `"pades"` | `"pkcs7"` or `"pades"` |
| `padesLevel` | | `"B-B"` | `"B-B"`, `"B-T"`, `"B-LT"`, `"B-LTA"` |
| `timestampUrl` | | `null` | TSA URL for B-T/B-LT/B-LTA |
| `includeCrl` | | `false` | Embed CRL data |
| `includeOcsp` | | `false` | Embed OCSP data |

**Response:**
```json
{
  "signedPdf": "<base64-encoded-signed-PDF>",
  "signatureFormat": "pades",
  "padesLevel": "B-B",
  "hasVisibleSignature": true
}
```

**Error responses:**
| HTTP | Error | Cause |
|------|-------|-------|
| 400 | `invalid_request` | Invalid Base64, missing `sigRect` when image is provided |
| 400 | `preparation_error` | PDF is corrupt or cannot be parsed |
| 401 | `invalid_token` | Missing or expired Bearer token |
| 403 | `invalid_request` | Credential ID not accessible |
| 500 | `server_error` | CMS build or embedding failure |

---

### signHash vs. signDoc vs. signPdf — Comparison

```
┌──────────────────────────────────────────────────────────────────┐
│  signHash                                                        │
│  Client: prepare PDF + compute hash → send 32 bytes              │
│  Server: wrap hash in CMS (manual DER) → return CMS              │
│  Client: embed CMS + DSS + doc-ts → output signed PDF            │
│  Calls: auth + credentials + signHash = 4 round-trips            │
│  TSA/LTV: ✅ All variants (B-B/B-T/B-LT/B-LTA, PKCS7 LTV)     │
│  Visible image: client-side only                                 │
│  Bandwidth: minimal (32 bytes over wire)                         │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  signDoc ⭐                                                       │
│  Client: prepare PDF → send byte-range content                   │
│  Server: hash + build CMS → return CMS                           │
│  Client: embed CMS into PDF                                      │
│  Calls: auth + credentials + signDoc = 4 round-trips             │
│  Visible image: client-side only                                 │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  signPdf ⭐⭐                                                      │
│  Client: upload PDF + image                                      │
│  Server: prepare + image + hash + CMS + embed → return PDF       │
│  Client: save result                                             │
│  Calls: auth + credentials + signPdf = 3 round-trips             │
│  Visible image: server-side rendering ✅                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
remote-signature-pdf/
├── Cargo.toml                    # Workspace with server + client binaries
├── PLAN.md                       # This file
├── certs/                        # Static test certificates
│   ├── generate_certs.sh         # Script to generate legacy test CA + user cert
│   ├── ca-cert.pem               # Legacy: self-signed CA cert
│   ├── ca-key.pem                # Legacy: CA private key
│   ├── user-cert.pem             # Legacy: user/signer cert
│   ├── user-key.pem              # Legacy: user private key
│   └── nowina/                   # Nowina DSS PKI Factory certs (3-level chain) ⭐
│       ├── user-cert.pem         # CN=good-user-crl-ocsp (with CRL+OCSP URLs)
│       ├── user-key.pem          # User private key (PKCS#8, 3072-bit RSA)
│       └── ca-chain.pem          # good-ca (intermediate) + root-ca (root)
│   ├── ca-cert.pem               # Self-signed CA certificate
│   ├── ca-key.pem                # CA private key
│   ├── user-cert.pem             # User/signer certificate (signed by CA)
│   └── user-key.pem              # User private key
├── test-files/                   # Test PDF files
│   └── sample.pdf                # A simple unsigned PDF for testing
├── examples/
│   ├── gen_test_pdf.rs           # Generate a test PDF for signing
│   └── test_all_variants.rs      # Test all signing variants with a P12 cert
├── src/
│   ├── main.rs                   # CLI entry point (server / sign / verify / validate)
│   ├── common/                   # Shared types between client & server
│   │   ├── mod.rs
│   │   └── csc_types.rs          # CSC API request/response + validation types
│   ├── server/                   # Server (PKI / TSP)
│   │   ├── mod.rs
│   │   ├── app.rs                # Actix-web app setup & routes
│   │   ├── auth.rs               # /auth/login — JWT token generation
│   │   ├── credentials.rs        # /credentials/list & /credentials/info
│   │   ├── signing.rs            # /signatures/signHash & /signatures/signDoc
│   │   ├── sign_pdf.rs           # /api/v1/signPdf — full server-side signing
│   │   ├── validation.rs         # /api/v1/validate — PDF signature validation
│   │   ├── info.rs               # /csc/v2/info endpoint
│   │   └── pki.rs                # Certificate loading, key management
│   └── client/                   # Client (PDF operations)
│       ├── mod.rs
│       ├── workflow.rs           # End-to-end signing orchestration
│       ├── pdf_preparer.rs       # PDF placeholder insertion & hash computation
│       ├── csc_client.rs         # HTTP client for CSC API + validate calls
│       └── pdf_finalizer.rs      # Embed CMS signature into PDF
```

---

## Implementation Plan — Step by Step

### Phase 1: Foundation & Shared Types ✅
**Goal:** Set up project, define CSC types, static certs

1. ✅ **Set up Cargo.toml** with dependencies:
   - `actix-web` (server HTTP framework)
   - `reqwest` (client HTTP)
   - `serde`, `serde_json` (serialization)
   - `base64` (encoding)
   - `sha2` (hashing)
   - `x509-certificate`, `cryptographic-message-syntax` (PKI/CMS)
   - `lopdf` (PDF manipulation)
   - `pdf_signing` (your existing library, as path dependency)
   - `clap` (CLI argument parsing)
   - `jsonwebtoken` (JWT for auth tokens)
   - `chrono` (timestamps)
   - `tokio` (async runtime)
   - `log`, `env_logger` (logging)
   - `uuid` (unique IDs)

2. ✅ **Define CSC API types** (`src/common/csc_types.rs`):
   - `InfoResponse`
   - `AuthLoginRequest` / `AuthLoginResponse`
   - `CredentialsListResponse`
   - `CredentialsInfoRequest` / `CredentialsInfoResponse`
   - `SignHashRequest` / `SignHashResponse`
   - `SignDocRequest` / `SignDocResponse` (extension for proper CMS)
   - `SignPdfRequest` / `SignPdfResponse` (full server-side signing)
   - `ErrorResponse`

3. ✅ **Generate test certificates** (`certs/generate_certs.sh`):
   - Self-signed CA
   - User certificate signed by CA
   - Store as PEM files

### Phase 2: Server — PKI Service ✅
**Goal:** Build the CSC-compliant signing server

4. ✅ **PKI module** (`src/server/pki.rs`):
   - Load CA cert + key from PEM files
   - Load user cert + key from PEM files
   - Store in `AppState` shared across handlers

5. ✅ **Info endpoint** (`src/server/info.rs`):
   - `POST /csc/v2/info` → return service metadata
   - Advertises both `signHash` and `signDoc` methods

6. ✅ **Auth endpoint** (`src/server/auth.rs`):
   - `POST /csc/v2/auth/login` → validate Basic Auth, return JWT
   - `validate_bearer_token()` helper for protected routes

7. ✅ **Credentials endpoints** (`src/server/credentials.rs`):
   - `POST /csc/v2/credentials/list` → return credential IDs
   - `POST /csc/v2/credentials/info` → return cert chain as Base64 DER

8. ✅ **Signing endpoints** (`src/server/signing.rs`):
   - `POST /csc/v2/signatures/signHash` — standard CSC (simplified)
   - `POST /csc/v2/signatures/signDoc` — extension: accepts raw content bytes,
     server builds complete CMS `SignedData` with correct `messageDigest`
   - Build CMS with ESS-signing-certificate-v2 attribute
   - User certificate chain embedded

8b. ✅ **Full server-side signing** (`src/server/sign_pdf.rs`):
    - `POST /api/v1/signPdf` — accepts complete PDF + optional image
    - Server handles entire pipeline: prepare → image → hash → CMS → embed
    - Returns fully signed PDF in a single HTTP round-trip
    - Reuses `pdf_preparer`, `signature_appearance`, `pdf_finalizer`, and `build_cms_with_options`
    - 50 MB JSON payload limit for large PDFs + images

### Phase 3: Client — PDF Preparation & Signing ✅
**Goal:** Build the client that prepares PDFs and calls the server

9. ✅ **CSC HTTP client** (`src/client/csc_client.rs`):
   - `info()` → get server metadata
   - `login()` → get access token
   - `list_credentials()` → get credential IDs
   - `get_credential_info()` → get cert chain
   - `sign_doc()` → send document content, get CMS signature

10. ✅ **PDF Preparer** (`src/client/pdf_preparer.rs`):
    - Load PDF via `lopdf::IncrementalDocument`
    - Insert signature placeholder (ByteRange + Contents fields)
    - Serialize to bytes
    - Fix ByteRange using robust `<`/`>` delimiter detection (no byte shifting)
    - Compute SHA-256 hash of the signed byte ranges
    - Return: `PreparedPdf { pdf_bytes, byte_range, content_to_sign, hash, signature_size }`

11. ✅ **PDF Finalizer** (`src/client/pdf_finalizer.rs`):
    - Take prepared PDF bytes + CMS signature from server
    - In-place, fixed-width write of hex-encoded CMS into Contents placeholder
    - Zero-padded to fill full placeholder (no byte shifting)
    - Output final signed PDF

12. ✅ **CLI** (`src/main.rs` with clap):
    ```
    # Start server
    remote-signature-pdf server --cert-dir ./certs --port 8080

    # Sign a PDF
    remote-signature-pdf sign \
      --server-url http://localhost:8080 \
      --input document.pdf \
      --output signed_document.pdf \
      --username testuser \
      --password testpass

    # Verify a signed PDF
    remote-signature-pdf verify --input signed.pdf
    ```

### Phase 4: Integration & Testing ✅
**Goal:** End-to-end flow works

13. ✅ **Integration test flow:**
    - Start server (with test certs)
    - Client loads `test-files/sample.pdf`
    - Client calls `/auth/login`
    - Client calls `/credentials/list` then `/credentials/info`
    - Client prepares PDF, computes hash
    - Client calls `/signatures/signDoc` with format & level options
    - Client embeds signature into PDF
    - Validate with `SignatureValidator` from `pdf_signing` lib

14. ✅ **Validation**: Use existing `signature_validator.rs` from `pdf_signing` to verify the output

### Phase 5: Enhancements ✅
**Goal:** Full feature coverage using all `pdf_signing` library capabilities

15. ✅ **Multiple signature formats:**
    - `PKCS7` (adbe.pkcs7.detached)
    - `PAdES` (ETSI.CAdES.detached)
    - CLI: `--format pkcs7` or `--format pades`

16. ✅ **PAdES conformance levels:**
    - `B-B` — Basic (ESS-signing-certificate-v2 only)
    - `B-T` — Timestamp (+ TSA signature timestamp)
    - `B-LT` — Long-Term (+ DSS dictionary with CRL/OCSP)
    - `B-LTA` — Long-Term Archival (+ document timestamp)
    - CLI: `--level B-B` / `--level B-T` / etc.
    - TSA URL: `--tsa-url http://timestamp.digicert.com`

17. ✅ **PDF validation endpoint:**
    - `POST /api/v1/validate` — accepts Base64-encoded PDF
    - Returns comprehensive `ValidateResponse` with per-signature details:
      - Cryptographic integrity (digest, CMS, chain)
      - ByteRange structural validation (USF defense)
      - Signature wrapping detection (SWA defense)
      - MDP certification permission checks
      - Modification detection after signing
      - LTV analysis (DSS, VRI, timestamps, revocation data)
      - Certificate chain details (expiry, self-signed, trusted)
    - Supports encrypted/password-protected PDFs

18. ✅ **Enhanced CLI commands:**
    - `sign` — with `--format`, `--level`, `--tsa-url` options
    - `sign` — with `--image`, `--sig-page`, `--sig-rect` for visible signatures
    - `verify` — comprehensive local validation output
    - `validate` — remote validation via server API

19. ✅ **Visible signature with image:**
    - `--image <path>` — PNG or JPEG signature image
    - `--sig-page <n>` — target page (1-based, default: 1)
    - `--sig-rect "x1,y1,x2,y2"` — position in PDF points (default: "50,50,250,150")
    - Decodes image via `image` crate (PNG/JPEG)
    - Creates PDF Image XObject with SMask for alpha transparency
    - Creates Form XObject appearance stream (`/AP /N`)
    - Sets widget annotation Rect for visible placement
    - Works with all signature formats (PAdES, PKCS7) and levels

20. ✅ **Server-side full signing** (`sign-remote` CLI + `/api/v1/signPdf`):
    - Upload PDF + optional image → server does everything → download signed PDF
    - `sign_pdf_remote()` client method for one-shot server-side signing
    - `prepare_pdf_for_signing_from_bytes()` for in-memory PDF loading via tempfile
    - Works with all formats (PAdES, PKCS7), levels, and visible/invisible modes

### Phase 6: Form-Data & API Documentation ✅
**Goal:** Production-ready API surface with file upload support

21. ✅ **Multipart form-data endpoints:**
    - `server/multipart.rs` — generic field extraction helper
    - `POST /api/v1/signPdf/form` — upload PDF + image, get binary PDF or JSON
    - `POST /api/v1/validate/form` — upload signed PDF for validation
    - `POST /csc/v2/signatures/signDoc/form` — upload byte-range content
    - Supports `responseFormat=binary` (raw PDF) or `json`

22. ✅ **OpenAPI 3.0 specification** (`docs/openapi.yaml`):
    - Full spec for all 11 endpoints with request/response schemas
    - Import into Swagger UI, Redoc, or any OpenAPI tool

23. ✅ **Postman collection** (`docs/postman_collection.json`):
    - 17 requests across 4 folders
    - Auto-saves Bearer token from login

24. ✅ **MIT License** (`LICENSE` file + Cargo.toml metadata)

### Phase 7: LTV / DSS / Timestamp Pipeline ✅
**Goal:** Proper PAdES B-LT/B-LTA and PKCS7 LTV support

25. ✅ **LTV module** (`server/ltv.rs`):
    - CRL/OCSP URL extraction from X.509 certificate extensions
    - HTTP fetching of CRL and OCSP responses
    - `adbe-revocationInfoArchival` CMS signed attribute construction
    - DSS (Document Security Store) dictionary appending to PDF
    - RFC 3161 timestamp token fetching
    - Document-level timestamp appending for B-LTA

26. ✅ **PAdES B-LT implementation:**
    - After CMS embedding: append DSS dictionary with CRLs, OCSPs, and certificates
    - Verified output: ~61KB (with DSS)

27. ✅ **PAdES B-LTA implementation:**
    - After DSS: append document-level timestamp via RFC 3161
    - Verified output: ~92KB (with DSS + document timestamp)

28. ✅ **PKCS7 LTV support:**
    - `includeCrl` / `includeOcsp` flags in signDoc and signPdf/form
    - CRL/OCSP data embedded as CMS signed attributes
    - CLI: `--include-crl` / `--include-ocsp` flags

29. ✅ **TSA deadlock fix:**
    - Wrapped `build_cms_with_options()` in `tokio::task::spawn_blocking()`
    - `cryptographic-message-syntax` uses synchronous HTTP internally
    - Prevents async runtime deadlock when contacting TSA servers

30. ✅ **Signature placeholder increase:**
    - Increased from 30,000 to 50,000 hex chars
    - Accommodates CMS with embedded CRL+OCSP revocation data

### Phase 8: Comprehensive Testing ✅
**Goal:** Full coverage across all signing variants

31. ✅ **Comprehensive test script** (`test-files/test_all_signing.sh`):
    - **Section A**: Client CLI — PAdES B-B/B-T/B-LT/B-LTA + PKCS7 + PKCS7 LTV (12 tests)
    - **Section B**: Server signPdf/form — PAdES 4×inv + 4×vis + PKCS7 ×4 + PKCS7 LTV ×5 (17 tests)
    - **Section C**: CSC signDoc/form — PAdES + PKCS7 + PKCS7 LTV variants (8 tests)
    - **Section D**: Server validation of all signed PDFs
    - **Section E**: CLI offline verification of all signed PDFs

### Phase 9: signHash Full Variant Support ✅
**Goal:** Extend signHash from simplified CMS to full signing variant support

32. ✅ **SignHashRequest extended** with optional `signatureFormat`, `padesLevel`, `timestampUrl`, `includeCrl`, `includeOcsp` fields (backward-compatible defaults)
33. ✅ **`build_cms_from_hash()` enhanced** — manual DER CMS construction now supports:
    - TSA timestamps via `timeStampToken` unsigned attribute (OID 1.2.840.113549.1.9.16.2.14)
    - CRL/OCSP revocation data via `adbe-revocationInfoArchival` signed attribute
    - Same format/level/TSA/CRL/OCSP logic as `build_cms_with_options()`
34. ✅ **Client `sign_hash()` updated** to forward all signing options to server
35. ✅ **`--use-sign-hash` CLI flag** — bandwidth-efficient alternative to signDoc
36. ✅ **Section AH test cases** — 13 signHash variants (PAdES all levels + PKCS7 + LTV)

### Phase 10: Client-Side DSS & Document Timestamp Fix ✅
**Goal:** Client-side PAdES B-LT/B-LTA must include post-CMS DSS and document timestamp

37. ✅ **Client workflow extended** with post-CMS processing:
    - Step 8a (B-LT, B-LTA): `append_dss_dictionary()` — CRL/OCSP/Certs incremental update
    - Step 8b (B-LTA): `append_document_timestamp()` — RFC 3161 document-level timestamp
    - Applies to both signDoc (Section A) and signHash (Section AH) flows
38. ✅ **`build_cert_chain_from_b64()`** helper — parses CSC credential cert chain for LTV module
39. ✅ **Verified output sizes**: B-LT ~61KB (with DSS), B-LTA ~91KB (with DSS + doc timestamp)
    - **Total: 134 tests — all passing ✅**

### Phase 11: Future Enhancements (Optional)
- Multiple signers / serial signing
- Credential authorization (SAD flow)
- WebSocket for long-running signing operations
- PKCS#11 / HSM integration for production key management

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| HTTP Framework | `actix-web` | Mature, async, good Rust ecosystem |
| Auth | JWT with Basic Auth login | Simple for prototype, CSC-compliant |
| Signature Format | CMS/PKCS#7 (PAdES) | Industry standard, matches existing lib |
| Certificate Storage | Static PEM files | Simple for prototype |
| PDF Library | `pdf_signing` (existing) | Already handles ByteRange, placeholder, CMS embedding |
| Hash Algorithm | SHA-256 | CSC default, widely supported |
| Sign Algorithm | RSA-SHA256 (1.2.840.113549.1.1.11) | Common, well-tested |
| TSA Integration | `spawn_blocking` | CMS lib uses sync HTTP; prevents tokio deadlock |
| LTV Data | CMS signed attributes + DSS | adbe-revocationInfoArchival for CRL/OCSP in CMS |
| Signature Placeholder | 50,000 hex chars | Accommodates CMS + CRL + OCSP revocation data |
| signHash CMS | Manual DER construction | Library always double-hashes; manual build uses hash directly as messageDigest |
| Client DSS/Timestamp | Post-CMS incremental update | Client appends DSS + doc-timestamp after embedding CMS for B-LT/B-LTA |
| Form-Data | `actix-multipart` | Direct file upload, no Base64 encoding needed |

---

## CSC Protocol Flow Diagram

```
Client                                    Server
  │                                          │
  │  POST /csc/v2/auth/login                 │
  │  (Basic Auth: user/pass)                 │
  ├─────────────────────────────────────────→│
  │  { access_token: "jwt..." }              │
  │←─────────────────────────────────────────┤
  │                                          │
  │  POST /csc/v2/credentials/list           │
  │  (Bearer: jwt)                           │
  ├─────────────────────────────────────────→│
  │  { credentialIDs: ["cred-001"] }         │
  │←─────────────────────────────────────────┤
  │                                          │
  │  POST /csc/v2/credentials/info           │
  │  { credentialID: "cred-001" }            │
  ├─────────────────────────────────────────→│
  │  { cert: { certificates: [...] } }       │
  │←─────────────────────────────────────────┤
  │                                          │
  │  [Client prepares PDF locally]           │
  │  [Computes SHA-256 of ByteRange]         │
  │                                          │
  │  POST /csc/v2/signatures/signHash        │
  │  { hashes: ["<b64-hash>"], ... }         │
  ├─────────────────────────────────────────→│
  │  { signatures: ["<b64-cms>"] }           │
  │←─────────────────────────────────────────┤
  │                                          │
  │  [Client embeds CMS into PDF Contents]   │
  │  [Saves signed PDF]                      │
  │                                          │
```

---

## Dependencies Summary

```toml
[dependencies]
# Server
actix-web = "4"
actix-rt = "2"
actix-multipart = "0.7"
jsonwebtoken = "9"

# Client HTTP
reqwest = { version = "0.12", features = ["json"] }

# Shared
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
sha2 = "0.10"
chrono = { version = "0.4", features = ["serde"] }
log = "0.4"
env_logger = "0.11"
uuid = { version = "1", features = ["v4"] }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
futures-util = "0.3"
tempfile = "3"

# PKI / Crypto
x509-certificate = "0.25"
cryptographic-message-syntax = "0.28"
bcder = "0.7"
x509-parser = "0.16"          # CRL/OCSP URL extraction from extensions
rasn = "0.22"                  # ASN.1 encoding
rasn-ocsp = "0.22"             # OCSP request/response
rasn-pkix = "0.22"             # X.509/PKI structures

# PDF (existing library)
pdf_signing = { path = "../rust_pdf_signing" }
lopdf = { version = "0.39", features = ["chrono"], default-features = false }

# Image processing
image = "0.25"
```

---

## Getting Started

```bash
# 1. Generate test certificates
cd certs && bash generate_certs.sh && cd ..

# 2. Generate a test PDF (if not present)
cargo run --example gen_test_pdf

# 3. Start the server (uses Nowina DSS 3-level PKI chain by default)
cargo run -- server --port 8080

# Or use legacy self-signed certs:
# cargo run -- server --cert-dir ./certs --port 8080

# 4. In another terminal — Sign with PAdES B-B (default)
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output test-files/signed.pdf

# 5. Sign with PKCS7 format
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output test-files/signed-pkcs7.pdf \
  --format pkcs7

# 6. Sign with PAdES B-T (timestamped)
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output test-files/signed-bt.pdf \
  --format pades --level B-T \
  --tsa-url http://timestamp.digicert.com

# 7. PKCS7 with LTV (CRL + OCSP + timestamp)
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output test-files/signed-pkcs7-ltv.pdf \
  --format pkcs7 --include-crl --include-ocsp \
  --tsa-url http://timestamp.digicert.com

# 8. Verify locally (comprehensive output)
cargo run -- verify --input test-files/signed.pdf

# 10. Validate via server API
cargo run -- validate \
  --server-url http://localhost:8080 \
  --input test-files/signed.pdf

# ── Server-side signing (sign-remote) ──

# 11. Server-side sign with visible image (one API call, server does everything)
cargo run -- sign-remote \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output test-files/signed-server.pdf \
  --image test-files/signature-image.png \
  --sig-rect "50,50,250,150" \
  --signer-name "John Doe"

# 12. Server-side sign without image (invisible)
cargo run -- sign-remote \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output test-files/signed-server-invisible.pdf
```

