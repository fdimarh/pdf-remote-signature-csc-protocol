# Remote Signature PDF

A **client-server** remote PDF digital signing system built in Rust, implementing the [Cloud Signature Consortium (CSC) API v2](https://cloudsignatureconsortium.org/resources/download-api-specifications/) protocol.

The **server** acts as a PKI / Trust Service Provider (TSP) managing X.509 certificates and performing CMS/PKCS#7 cryptographic signing. The **client** prepares PDFs and orchestrates the remote signing flow. Both run as a single binary with subcommands.

---

## Features

- **CSC v2 Protocol** — Standards-based remote signing with `signHash` and `signDoc` endpoints
- **Full Server-Side Signing** — Upload a PDF + optional image, get back a fully signed PDF in one call (`signPdf`)
- **Multiple Signature Formats** — PKCS#7 (`adbe.pkcs7.detached`) and PAdES (`ETSI.CAdES.detached`)
- **PAdES Conformance Levels** — B-B, B-T (timestamped), B-LT (long-term with DSS), B-LTA (archival with doc timestamp)
- **LTV / Long-Term Validation** — CRL/OCSP revocation data embedded in CMS, DSS dictionary appended to PDF, document timestamps for B-LTA
- **PKCS7 LTV Support** — `--include-crl` / `--include-ocsp` flags for embedding revocation data in PKCS#7 signatures
- **Visible Signatures** — Embed a PNG/JPEG image as a visible signature on any page (client-side or server-side rendering)
- **Comprehensive Validation** — 20+ cryptographic and structural checks (digest, chain, ByteRange, wrapping attacks, MDP, LTV)
- **Multi-Level Certificate Chains** — Supports 2-level (self-signed) and 3-level (Nowina DSS) PKI chains
- **TSA Timestamp Support** — Integrates with external Timestamp Authorities (e.g., DigiCert) for B-T/B-LT/B-LTA levels
- **Form-Data Upload** — All signing/validation endpoints support `multipart/form-data` with binary PDF response
- **OpenAPI 3.0 Spec** — Machine-readable API spec at `docs/openapi.yaml`
- **Postman Collection** — Ready-to-use collection at `docs/postman_collection.json`
- **95 Automated Tests** — Comprehensive test suite covering all signing variants, validation, and verification

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         CLIENT                                │
│                                                               │
│  sign       — Prepare PDF locally, send content to server     │
│  sign-remote — Upload PDF to server (server does everything)  │
│  verify     — Local signature validation                      │
│  validate   — Remote validation via server API                │
└───────────────────────┬──────────────────────────────────────┘
                        │  REST API (HTTP/JSON)
                        ▼
┌──────────────────────────────────────────────────────────────┐
│                         SERVER                                │
│                                                               │
│  /csc/v2/info              — Service metadata                 │
│  /csc/v2/auth/login        — Basic Auth → Bearer token        │
│  /csc/v2/credentials/list  — List signing credentials         │
│  /csc/v2/credentials/info  — Certificate chain details        │
│  /csc/v2/signatures/signHash — Sign a hash (standard CSC)     │
│  /csc/v2/signatures/signDoc  — Sign content (recommended)     │
│  /api/v1/signPdf           — Full server-side signing ⭐       │
│  /api/v1/validate          — Validate signed PDF              │
│                                                               │
│  PKI Backend: Nowina DSS 3-level chain (default)              │
│  CN=good-user-crl-ocsp → CN=good-ca → CN=root-ca             │
└──────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (1.75+)
- The `pdf_signing` library at `../rust_pdf_signing` (sibling directory)

### Build

```bash
cargo build
```

### 1. Start the Server

```bash
# Uses Nowina DSS 3-level PKI chain by default
cargo run -- server --port 8080

# Or use legacy self-signed certs:
cargo run -- server --cert-dir ./certs --port 8080
```

### 2. Sign a PDF

**Client-side preparation** (PDF prep happens locally, server only signs):

```bash
# PAdES B-B (default)
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed.pdf

# PKCS#7 format
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed-pkcs7.pdf \
  --format pkcs7

# PAdES B-T with timestamp
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed-bt.pdf \
  --level B-T \
  --tsa-url http://timestamp.digicert.com

# With visible signature image
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed-visible.pdf \
  --image signature.png \
  --sig-rect "50,50,250,150" \
  --sig-page 1

# PKCS#7 with LTV (CRL + OCSP + timestamp)
cargo run -- sign \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed-pkcs7-ltv.pdf \
  --format pkcs7 \
  --include-crl --include-ocsp \
  --tsa-url http://timestamp.digicert.com
```

**Server-side signing** (server handles everything in one call):

```bash
# With visible signature image
cargo run -- sign-remote \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed-server.pdf \
  --image signature.png \
  --sig-rect "50,50,250,150" \
  --signer-name "John Doe"

# Invisible signature
cargo run -- sign-remote \
  --server-url http://localhost:8080 \
  --input test-files/sample.pdf \
  --output signed-server.pdf
```

### 3. Verify a Signed PDF

```bash
# Local verification (no server needed)
cargo run -- verify --input signed.pdf

# Remote validation via server API
cargo run -- validate \
  --server-url http://localhost:8080 \
  --input signed.pdf
```

---

## Signing Modes Compared

| | `signHash` | `signDoc` ⭐ | `signPdf` ⭐⭐ |
|---|---|---|---|
| **Client sends** | 32-byte hash | Byte-range content | Full PDF + optional image |
| **Server returns** | CMS blob | CMS blob | Fully signed PDF |
| **PDF prep** | Client | Client | Server |
| **CMS building** | Server (simplified) | Server (correct) | Server (correct) |
| **Embedding** | Client | Client | Server |
| **Visible image** | Client-side only | Client-side only | Server-side rendering ✅ |
| **Round-trips** | 4 | 4 | 3 |
| **Best for** | CSC compliance | Production signing | Simplest integration |

---

## API Reference

### Authentication

All endpoints (except `/csc/v2/info`) require a Bearer token obtained from login:

```bash
# Login
curl -X POST http://localhost:8080/csc/v2/auth/login \
  -H "Authorization: Basic $(echo -n testuser:testpass | base64)" \
  -H "Content-Type: application/json" \
  -d '{"rememberMe": true}'

# Returns: { "access_token": "...", "token_type": "Bearer", "expires_in": 3600 }
```

Default test credentials: `testuser` / `testpass`

### Endpoints

| Method | Path | Auth | Content-Type | Description |
|--------|------|------|--------------|-------------|
| POST | `/csc/v2/info` | No | JSON | Service metadata and capabilities |
| POST | `/csc/v2/auth/login` | Basic | JSON | Authenticate and get Bearer token |
| POST | `/csc/v2/credentials/list` | Bearer | JSON | List available signing credentials |
| POST | `/csc/v2/credentials/info` | Bearer | JSON | Get certificate chain and key info |
| POST | `/csc/v2/signatures/signHash` | Bearer | JSON | Sign a SHA-256 hash (standard CSC) |
| POST | `/csc/v2/signatures/signDoc` | Bearer | JSON | Sign byte-range content (recommended) |
| POST | `/csc/v2/signatures/signDoc/form` | Bearer | **form-data** | Sign byte-range content (file upload) |
| POST | `/api/v1/signPdf` | Bearer | JSON | Full server-side PDF signing |
| POST | `/api/v1/signPdf/form` | Bearer | **form-data** | Full server-side PDF signing (file upload) |
| POST | `/api/v1/validate` | No | JSON | Validate a signed PDF |
| POST | `/api/v1/validate/form` | No | **form-data** | Validate a signed PDF (file upload) |

### `POST /api/v1/signPdf` — Full Server-Side Signing

```json
{
  "credentialID": "credential-001",
  "pdfContent": "<base64-encoded-PDF>",
  "imageContent": "<base64-encoded-PNG-or-JPEG>",
  "sigRect": [50, 50, 250, 150],
  "sigPage": 1,
  "signerName": "John Doe",
  "signatureFormat": "pades",
  "padesLevel": "B-B"
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `credentialID` | ✅ | — | Signing credential ID |
| `pdfContent` | ✅ | — | Base64-encoded PDF file |
| `imageContent` | | `null` | Base64-encoded PNG/JPEG for visible signature |
| `sigRect` | when image | — | `[x1, y1, x2, y2]` in PDF points |
| `sigPage` | | `1` | Target page (1-based) |
| `signerName` | | `"Digital Signature"` | Signer display name |
| `signatureFormat` | | `"pades"` | `"pkcs7"` or `"pades"` |
| `padesLevel` | | `"B-B"` | `"B-B"`, `"B-T"`, `"B-LT"`, `"B-LTA"` |
| `timestampUrl` | | `null` | TSA URL for timestamped levels |

### `POST /api/v1/validate` — Signature Validation

```json
{
  "pdfContent": "<base64-encoded-signed-PDF>"
}
```

Returns per-signature validation results including:

| Check | What it verifies |
|-------|------------------|
| `digestMatch` | SHA-256 of byte ranges matches CMS messageDigest |
| `cmsSignatureValid` | RSA signature over signed attributes is correct |
| `certificateChainValid` | Certificate chain is complete and none expired |
| `byteRangeValid` | ByteRange starts at 0, no gaps or overlaps (USF defense) |
| `signatureNotWrapped` | Contents is exactly in the ByteRange gap (SWA defense) |
| `noUnauthorizedModifications` | No tampering after signing |
| `certificationPermissionOk` | MDP permissions respected |
| `hasTimestamp` | CMS contains a TSA timestamp |
| `isLtvEnabled` | DSS dictionary present for long-term validation |

---

### Form-Data Endpoints (Multipart File Upload)

All `/form` endpoints accept `multipart/form-data` — no Base64 encoding needed. Files are uploaded directly with `curl -F`.

#### `POST /api/v1/signPdf/form` — Sign PDF via file upload

```bash
# Sign with visible signature → get raw PDF back
curl -X POST http://localhost:8080/api/v1/signPdf/form \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@document.pdf" \
  -F "image=@signature.png" \
  -F "sigRect=50,50,250,150" \
  -F "signerName=John Doe" \
  -F "signatureFormat=pades" \
  -F "padesLevel=B-B" \
  -o signed.pdf

# Sign invisible → get JSON response
curl -X POST http://localhost:8080/api/v1/signPdf/form \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@document.pdf" \
  -F "responseFormat=json"
```

| Form Field | Required | Default | Description |
|------------|----------|---------|-------------|
| `file` | ✅ | — | PDF file upload |
| `image` | | — | PNG/JPEG signature image file upload |
| `credentialID` | | `credential-001` | Signing credential |
| `signerName` | | `Digital Signature` | Signer display name |
| `signatureFormat` | | `pades` | `pkcs7` or `pades` |
| `padesLevel` | | `B-B` | PAdES level |
| `sigRect` | when image | `50,50,250,150` | `x1,y1,x2,y2` in PDF points |
| `sigPage` | | `1` | Page number (1-based) |
| `timestampUrl` | | — | TSA URL |
| `includeCrl` | | `false` | Embed CRL data |
| `includeOcsp` | | `false` | Embed OCSP data |
| `responseFormat` | | `binary` | `binary` (raw PDF) or `json` |

**Response formats:**
- `binary` (default): `Content-Type: application/pdf` with raw PDF bytes
- `json`: Same JSON structure as `/api/v1/signPdf`

#### `POST /api/v1/validate/form` — Validate via file upload

```bash
curl -X POST http://localhost:8080/api/v1/validate/form \
  -F "file=@signed.pdf"
```

| Form Field | Required | Description |
|------------|----------|-------------|
| `file` | ✅ | Signed PDF file upload |
| `password` | | Password for encrypted PDFs |

#### `POST /csc/v2/signatures/signDoc/form` — Sign content via file upload

```bash
curl -X POST http://localhost:8080/csc/v2/signatures/signDoc/form \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@byte_range_content.bin" \
  -F "signatureFormat=pades"
```

| Form Field | Required | Default | Description |
|------------|----------|---------|-------------|
| `file` | ✅ | — | Byte-range content file |
| `credentialID` | | `credential-001` | Signing credential |
| `signatureFormat` | | `pades` | `pkcs7` or `pades` |
| `padesLevel` | | `B-B` | PAdES level |
| `responseFormat` | | `json` | `json` or `binary` (raw CMS DER) |

---

## PKI Certificates

### Nowina DSS (Default)

3-level certificate chain from [Nowina DSS PKI Factory](https://dss.nowina.lu/pki-factory):

```
CN=good-user-crl-ocsp  (User/Signer, 3072-bit RSA)
  └─ CN=good-ca          (Intermediate CA)
       └─ CN=root-ca      (Root CA, self-signed)
```

- Includes CRL distribution points and OCSP responder URLs
- Source: `good-user-crl-ocsp.p12` with password `ks-password`
- Located in `certs/nowina/`

### Legacy Self-Signed

2-level chain for local testing:

```
CN=Test Signer  (User/Signer)
  └─ CN=CSC Prototype Root CA  (Self-signed CA)
```

- Generated with `certs/generate_certs.sh`
- Located in `certs/`

The server auto-detects the layout: if `ca-chain.pem` exists in the cert directory, it loads a multi-cert chain; otherwise it falls back to single `ca-cert.pem`.

---

## Project Structure

```
remote-signature-pdf/
├── Cargo.toml
├── LICENSE                            # MIT License
├── README.md
├── PLAN.md                            # Detailed architecture & API reference
├── docs/
│   ├── openapi.yaml                   # OpenAPI 3.0 specification
│   └── postman_collection.json        # Postman collection (import-ready)
├── certs/
│   ├── generate_certs.sh              # Generate legacy self-signed certs
│   ├── ca-cert.pem, ca-key.pem        # Legacy CA
│   ├── user-cert.pem, user-key.pem    # Legacy user
│   └── nowina/                         # Nowina DSS 3-level chain ⭐
│       ├── user-cert.pem               # CN=good-user-crl-ocsp
│       ├── user-key.pem               # PKCS#8, 3072-bit RSA
│       └── ca-chain.pem               # Intermediate + Root CA
├── src/
│   ├── main.rs                         # CLI: server, sign, sign-remote, verify, validate
│   ├── common/
│   │   └── csc_types.rs                # Shared CSC API request/response types
│   ├── server/
│   │   ├── app.rs                      # Actix-web app setup & routing
│   │   ├── auth.rs                     # JWT authentication
│   │   ├── credentials.rs              # Credential listing & cert chain
│   │   ├── info.rs                     # Service metadata
│   │   ├── ltv.rs                      # CRL/OCSP/DSS/timestamp (LTV pipeline) ⭐
│   │   ├── multipart.rs               # Form-data upload helper utilities
│   │   ├── pki.rs                      # PKI loading (multi-level chain support)
│   │   ├── signing.rs                  # signHash & signDoc (JSON + form-data)
│   │   ├── sign_pdf.rs                # signPdf (JSON + form-data, binary response)
│   │   └── validation.rs              # Validate (JSON + form-data)
│   └── client/
│       ├── csc_client.rs               # HTTP client for all CSC API + signPdf
│       ├── pdf_preparer.rs             # PDF placeholder & hash computation
│       ├── signature_appearance.rs     # Visible signature image → PDF XObject
│       ├── pdf_finalizer.rs            # Embed CMS into PDF
│       └── workflow.rs                 # End-to-end signing orchestration
├── examples/
│   ├── gen_test_pdf.rs                 # Generate a test PDF
│   ├── gen_test_signature_image.rs     # Generate a test signature PNG
│   └── test_all_variants.rs            # Test all format/level combinations
└── test-files/
    ├── sample.pdf                      # Test input PDF
    ├── signature-image.png             # Test signature image
    ├── test_all_signing.sh             # Comprehensive test suite (95 tests) ⭐
    └── all-signing-test-report.txt     # Test report (95/95 passed)
```

---

## CLI Reference

```
remote-signature-pdf <COMMAND>

Commands:
  server       Start the CSC signing server
  sign         Sign a PDF (client-side prep, remote CMS)
  sign-remote  Sign a PDF entirely on the server
  verify       Verify a signed PDF locally
  validate     Validate a signed PDF via server API
```

### `server`

```
Options:
  --cert-dir <DIR>    Certificate directory [default: ./certs/nowina]
  --host <HOST>       Bind address [default: 127.0.0.1]
  --port <PORT>       Listen port [default: 8080]
```

### `sign`

```
Options:
  --server-url <URL>    CSC server URL [default: http://localhost:8080]
  --input, -i <FILE>    Input PDF
  --output, -o <FILE>   Output signed PDF
  --username, -u <STR>  Username [default: testuser]
  --password, -p <STR>  Password [default: testpass]
  --format, -f <FMT>    "pkcs7" or "pades" [default: pades]
  --level, -l <LVL>     "B-B", "B-T", "B-LT", "B-LTA" [default: B-B]
  --tsa-url <URL>       Timestamp Authority URL
  --image <FILE>        Signature image (PNG/JPEG) for visible signature
  --sig-page <NUM>      Page number [default: 1]
  --sig-rect <RECT>     "x1,y1,x2,y2" in PDF points [default: 50,50,250,150]
  --include-crl         Include CRL revocation data in CMS (PKCS7 LTV)
  --include-ocsp        Include OCSP revocation data in CMS (PKCS7 LTV)
```

### `sign-remote`

```
Options:
  --server-url <URL>     CSC server URL [default: http://localhost:8080]
  --input, -i <FILE>     Input PDF
  --output, -o <FILE>    Output signed PDF
  --username, -u <STR>   Username [default: testuser]
  --password, -p <STR>   Password [default: testpass]
  --format, -f <FMT>     "pkcs7" or "pades" [default: pades]
  --level, -l <LVL>      PAdES level [default: B-B]
  --tsa-url <URL>        Timestamp Authority URL
  --image <FILE>         Signature image for server-side rendering
  --sig-page <NUM>       Page number [default: 1]
  --sig-rect <RECT>      "x1,y1,x2,y2" [default: 50,50,250,150]
  --signer-name <NAME>   Display name [default: Digital Signature]
```

### `verify`

```
Options:
  --input, -i <FILE>    Signed PDF to verify
  --password <STR>      Password for encrypted PDFs
```

### `validate`

```
Options:
  --server-url <URL>    CSC server URL [default: http://localhost:8080]
  --input, -i <FILE>    Signed PDF to validate
  --password <STR>      Password for encrypted PDFs
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `actix-web` | HTTP server framework |
| `reqwest` | HTTP client |
| `serde` / `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |
| `x509-certificate` | X.509 certificate parsing and CMS building |
| `cryptographic-message-syntax` | CMS/PKCS#7 SignedData builder |
| `x509-parser` | X.509 extension parsing (CRL/OCSP URLs) |
| `rasn` / `rasn-ocsp` / `rasn-pkix` | ASN.1/OCSP request/response encoding |
| `sha2` | SHA-256 hashing |
| `lopdf` | PDF structure manipulation |
| `pdf_signing` | PDF signature validation (local path dep) |
| `image` | PNG/JPEG decoding for visible signatures |
| `jsonwebtoken` | JWT Bearer token generation |
| `base64` | Base64 encoding/decoding |
| `actix-multipart` | Multipart form-data file uploads |
| `futures-util` | Async stream processing for multipart |
| `tempfile` | Temporary files for server-side PDF loading |

---

## API Documentation

- **OpenAPI 3.0 Spec**: [`docs/openapi.yaml`](docs/openapi.yaml) — Import into Swagger UI, Redoc, or any OpenAPI tool
- **Postman Collection**: [`docs/postman_collection.json`](docs/postman_collection.json) — Import into Postman for interactive testing

---

## License

This project is licensed under the [MIT License](LICENSE).

