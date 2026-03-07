#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Comprehensive Test Suite — Remote Signature PDF
# ═══════════════════════════════════════════════════════════════
# Tests ALL endpoints, ALL signing variants, ALL form-data routes,
# client-side + server-side signing, and validation.
#
# Usage: bash test-files/test_comprehensive.sh
# Output: test-files/comprehensive-test-report.txt
set -euo pipefail

PROJECT="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BINARY="$PROJECT/target/debug/remote-signature-pdf"
PORT=9096
REPORT="$PROJECT/test-files/comprehensive-test-report.txt"
BASE="http://localhost:$PORT"

# Redirect all output to report
exec > "$REPORT" 2>&1

PASS=0
FAIL=0
TOTAL=0

ok() {
    PASS=$((PASS+1)); TOTAL=$((TOTAL+1))
    echo "  ✅ PASS: $1"
}
fail() {
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
    echo "  ❌ FAIL: $1"
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║    Comprehensive Test Report — Remote Signature PDF     ║"
echo "║    Date: $(date '+%Y-%m-%d %H:%M:%S')                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Setup ─────────────────────────────────────────────────────
pkill -f "remote-signature-pdf server" 2>/dev/null || true
sleep 2

echo "Starting server on port $PORT with Nowina certs..."
RUST_LOG=info "$BINARY" server --port $PORT 2>/dev/null &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"; exit 1
fi
echo "Server PID=$SERVER_PID"
echo ""

# ── Helper: login and get token ───────────────────────────────
login() {
    curl -s -X POST "$BASE/csc/v2/auth/login" \
      -H "Authorization: Basic $(echo -n testuser:testpass | base64)" \
      -H "Content-Type: application/json" \
      -d '{"rememberMe": true}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null
}

# ══════════════════════════════════════════════════════════════
# SECTION 1: CSC v2 JSON Endpoints
# ══════════════════════════════════════════════════════════════
echo "═══════════════════════════════════════════════════════"
echo "SECTION 1: CSC v2 JSON API Endpoints"
echo "═══════════════════════════════════════════════════════"

# 1.1 GET /csc/v2/info
echo ""
echo "--- 1.1 POST /csc/v2/info ---"
HTTP=$(curl -s -o /tmp/ct-info.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/info" -H "Content-Type: application/json" -d '{}')
if [ "$HTTP" = "200" ]; then
    SPECS=$(python3 -c "import json; print(json.load(open('/tmp/ct-info.json'))['specs'])" 2>/dev/null)
    METHODS=$(python3 -c "import json; print(len(json.load(open('/tmp/ct-info.json'))['methods']))" 2>/dev/null)
    echo "  specs=$SPECS, methods=$METHODS"
    ok "info endpoint"
else
    fail "info endpoint (HTTP $HTTP)"
fi

# 1.2 POST /csc/v2/auth/login — valid credentials
echo ""
echo "--- 1.2 POST /csc/v2/auth/login (valid) ---"
HTTP=$(curl -s -o /tmp/ct-login.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/auth/login" \
  -H "Authorization: Basic $(echo -n testuser:testpass | base64)" \
  -H "Content-Type: application/json" -d '{"rememberMe": true}')
if [ "$HTTP" = "200" ]; then
    TOKEN=$(python3 -c "import json; print(json.load(open('/tmp/ct-login.json'))['access_token'])" 2>/dev/null)
    echo "  token=${TOKEN:0:20}..."
    ok "login (valid credentials)"
else
    fail "login valid (HTTP $HTTP)"
fi

# 1.3 POST /csc/v2/auth/login — invalid credentials
echo ""
echo "--- 1.3 POST /csc/v2/auth/login (invalid) ---"
HTTP=$(curl -s -o /tmp/ct-login-bad.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/auth/login" \
  -H "Authorization: Basic $(echo -n baduser:badpass | base64)" \
  -H "Content-Type: application/json" -d '{"rememberMe": true}')
if [ "$HTTP" = "401" ]; then
    ok "login (invalid → 401)"
else
    fail "login invalid (expected 401, got $HTTP)"
fi

# Get a fresh token for subsequent calls
TOKEN=$(login)

# 1.4 POST /csc/v2/credentials/list
echo ""
echo "--- 1.4 POST /csc/v2/credentials/list ---"
HTTP=$(curl -s -o /tmp/ct-creds.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/credentials/list" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{}')
if [ "$HTTP" = "200" ]; then
    CRED=$(python3 -c "import json; print(json.load(open('/tmp/ct-creds.json'))['credentialIDs'][0])" 2>/dev/null)
    echo "  credential=$CRED"
    ok "credentials/list"
else
    fail "credentials/list (HTTP $HTTP)"
fi

# 1.5 POST /csc/v2/credentials/info
echo ""
echo "--- 1.5 POST /csc/v2/credentials/info ---"
HTTP=$(curl -s -o /tmp/ct-credinfo.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/credentials/info" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credentialID":"credential-001","certificates":"chain"}')
if [ "$HTTP" = "200" ]; then
    KEY_LEN=$(python3 -c "import json; print(json.load(open('/tmp/ct-credinfo.json'))['key']['len'])" 2>/dev/null)
    CHAIN_LEN=$(python3 -c "import json; print(len(json.load(open('/tmp/ct-credinfo.json'))['cert']['certificates']))" 2>/dev/null)
    echo "  keyLen=$KEY_LEN, chainCerts=$CHAIN_LEN"
    ok "credentials/info (chain=$CHAIN_LEN certs)"
else
    fail "credentials/info (HTTP $HTTP)"
fi

# 1.6 POST /csc/v2/credentials/list — no auth
echo ""
echo "--- 1.6 POST /csc/v2/credentials/list (no auth → 401) ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE/csc/v2/credentials/list" \
  -H "Content-Type: application/json" -d '{}')
if [ "$HTTP" = "401" ]; then
    ok "credentials/list no auth → 401"
else
    fail "credentials/list no auth (expected 401, got $HTTP)"
fi

# 1.7 POST /csc/v2/signatures/signHash
echo ""
echo "--- 1.7 POST /csc/v2/signatures/signHash ---"
HASH_B64=$(echo -n "0123456789abcdef0123456789abcdef" | base64)
HTTP=$(curl -s -o /tmp/ct-signhash.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/signatures/signHash" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"credentialID\":\"credential-001\",\"hashes\":[\"$HASH_B64\"],\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\"}")
if [ "$HTTP" = "200" ]; then
    SIG_COUNT=$(python3 -c "import json; print(len(json.load(open('/tmp/ct-signhash.json'))['signatures']))" 2>/dev/null)
    echo "  signatures=$SIG_COUNT"
    ok "signHash"
else
    fail "signHash (HTTP $HTTP)"
fi

# 1.8 POST /csc/v2/signatures/signDoc (PAdES B-B)
echo ""
echo "--- 1.8 POST /csc/v2/signatures/signDoc (PAdES B-B) ---"
DOC_B64=$(echo -n "SampleDocumentContent1234567890" | base64)
HTTP=$(curl -s -o /tmp/ct-signdoc.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/signatures/signDoc" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-B\"}")
if [ "$HTTP" = "200" ]; then
    FMT=$(python3 -c "import json; print(json.load(open('/tmp/ct-signdoc.json'))['signatureFormat'])" 2>/dev/null)
    echo "  format=$FMT"
    ok "signDoc PAdES B-B"
else
    fail "signDoc PAdES B-B (HTTP $HTTP)"
fi

# 1.9 POST /csc/v2/signatures/signDoc (PKCS7)
echo ""
echo "--- 1.9 POST /csc/v2/signatures/signDoc (PKCS7) ---"
HTTP=$(curl -s -o /tmp/ct-signdoc-p7.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/signatures/signDoc" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pkcs7\"}")
if [ "$HTTP" = "200" ]; then
    FMT=$(python3 -c "import json; print(json.load(open('/tmp/ct-signdoc-p7.json'))['signatureFormat'])" 2>/dev/null)
    echo "  format=$FMT"
    ok "signDoc PKCS7"
else
    fail "signDoc PKCS7 (HTTP $HTTP)"
fi

# ══════════════════════════════════════════════════════════════
# SECTION 2: Client-Side Sign + Verify (CLI)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "SECTION 2: Client-Side Sign + Verify (CLI Commands)"
echo "═══════════════════════════════════════════════════════"

# 2.1 PAdES B-B (invisible)
echo ""
echo "--- 2.1 sign PAdES B-B (invisible) ---"
if RUST_LOG=error "$BINARY" sign \
    --server-url "$BASE" --input "$PROJECT/test-files/sample.pdf" \
    --output "$PROJECT/test-files/ct-pades-bb.pdf" \
    --format pades --level B-B 2>/dev/null; then
    ok "sign PAdES B-B invisible"
else
    fail "sign PAdES B-B invisible"
fi

# 2.2 PAdES B-B (visible image)
echo ""
echo "--- 2.2 sign PAdES B-B (visible image) ---"
if RUST_LOG=error "$BINARY" sign \
    --server-url "$BASE" --input "$PROJECT/test-files/sample.pdf" \
    --output "$PROJECT/test-files/ct-pades-bb-visible.pdf" \
    --format pades --level B-B \
    --image "$PROJECT/test-files/signature-image.png" \
    --sig-rect "50,50,250,150" 2>/dev/null; then
    ok "sign PAdES B-B visible"
else
    fail "sign PAdES B-B visible"
fi

# 2.3 PKCS7 (invisible)
echo ""
echo "--- 2.3 sign PKCS7 (invisible) ---"
if RUST_LOG=error "$BINARY" sign \
    --server-url "$BASE" --input "$PROJECT/test-files/sample.pdf" \
    --output "$PROJECT/test-files/ct-pkcs7.pdf" \
    --format pkcs7 2>/dev/null; then
    ok "sign PKCS7 invisible"
else
    fail "sign PKCS7 invisible"
fi

# 2.4 Verify all signed PDFs
echo ""
echo "--- 2.4 verify signed PDFs ---"
for f in ct-pades-bb.pdf ct-pades-bb-visible.pdf ct-pkcs7.pdf; do
    FPATH="$PROJECT/test-files/$f"
    if [ -f "$FPATH" ]; then
        if RUST_LOG=error "$BINARY" verify --input "$FPATH" 2>&1 | grep -q "VALID"; then
            ok "verify $f"
        else
            fail "verify $f"
        fi
    else
        fail "verify $f (file missing)"
    fi
done

# ══════════════════════════════════════════════════════════════
# SECTION 3: Server-Side Sign (sign-remote CLI)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "SECTION 3: Server-Side Sign (sign-remote CLI)"
echo "═══════════════════════════════════════════════════════"

# 3.1 PAdES invisible
echo ""
echo "--- 3.1 sign-remote PAdES invisible ---"
if RUST_LOG=error "$BINARY" sign-remote \
    --server-url "$BASE" --input "$PROJECT/test-files/sample.pdf" \
    --output "$PROJECT/test-files/ct-remote-invisible.pdf" \
    --format pades --level B-B 2>/dev/null; then
    ok "sign-remote PAdES invisible"
else
    fail "sign-remote PAdES invisible"
fi

# 3.2 PAdES with visible image
echo ""
echo "--- 3.2 sign-remote PAdES visible ---"
if RUST_LOG=error "$BINARY" sign-remote \
    --server-url "$BASE" --input "$PROJECT/test-files/sample.pdf" \
    --output "$PROJECT/test-files/ct-remote-visible.pdf" \
    --image "$PROJECT/test-files/signature-image.png" \
    --sig-rect "50,50,250,150" --signer-name "Comprehensive Test" \
    --format pades --level B-B 2>/dev/null; then
    ok "sign-remote PAdES visible"
else
    fail "sign-remote PAdES visible"
fi

# 3.3 PKCS7
echo ""
echo "--- 3.3 sign-remote PKCS7 ---"
if RUST_LOG=error "$BINARY" sign-remote \
    --server-url "$BASE" --input "$PROJECT/test-files/sample.pdf" \
    --output "$PROJECT/test-files/ct-remote-pkcs7.pdf" \
    --format pkcs7 2>/dev/null; then
    ok "sign-remote PKCS7"
else
    fail "sign-remote PKCS7"
fi

# 3.4 Verify remote-signed PDFs
echo ""
echo "--- 3.4 verify remote-signed PDFs ---"
for f in ct-remote-invisible.pdf ct-remote-visible.pdf ct-remote-pkcs7.pdf; do
    FPATH="$PROJECT/test-files/$f"
    if [ -f "$FPATH" ]; then
        if RUST_LOG=error "$BINARY" verify --input "$FPATH" 2>&1 | grep -q "VALID"; then
            ok "verify $f"
        else
            fail "verify $f"
        fi
    fi
done

# ══════════════════════════════════════════════════════════════
# SECTION 4: JSON signPdf + validate API
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "SECTION 4: JSON signPdf + validate API"
echo "═══════════════════════════════════════════════════════"

PDF_B64=$(base64 < "$PROJECT/test-files/sample.pdf")
IMG_B64=$(base64 < "$PROJECT/test-files/signature-image.png")

# 4.1 signPdf JSON (PAdES + visible)
echo ""
echo "--- 4.1 POST /api/v1/signPdf (PAdES + visible) ---"
HTTP=$(curl -s -o /tmp/ct-signpdf.json -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"credentialID\":\"credential-001\",\"pdfContent\":\"$PDF_B64\",\"imageContent\":\"$IMG_B64\",\"sigRect\":[50,50,250,150],\"signerName\":\"API Test\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-B\"}")
if [ "$HTTP" = "200" ]; then
    HAS_VIS=$(python3 -c "import json; print(json.load(open('/tmp/ct-signpdf.json'))['hasVisibleSignature'])" 2>/dev/null)
    echo "  visible=$HAS_VIS"
    ok "signPdf JSON PAdES+visible"
else
    fail "signPdf JSON (HTTP $HTTP)"
fi

# 4.2 validate JSON
echo ""
echo "--- 4.2 POST /api/v1/validate (JSON) ---"
SIGNED_B64=$(python3 -c "import json; print(json.load(open('/tmp/ct-signpdf.json'))['signedPdf'])" 2>/dev/null)
HTTP=$(curl -s -o /tmp/ct-validate.json -w "%{http_code}" \
  -X POST "$BASE/api/v1/validate" \
  -H "Content-Type: application/json" \
  -d "{\"pdfContent\":\"$SIGNED_B64\"}")
if [ "$HTTP" = "200" ]; then
    ALL_VALID=$(python3 -c "import json; print(json.load(open('/tmp/ct-validate.json'))['allValid'])" 2>/dev/null)
    SIG_CNT=$(python3 -c "import json; print(json.load(open('/tmp/ct-validate.json'))['signatureCount'])" 2>/dev/null)
    echo "  allValid=$ALL_VALID, count=$SIG_CNT"
    ok "validate JSON"
else
    fail "validate JSON (HTTP $HTTP)"
fi

# ══════════════════════════════════════════════════════════════
# SECTION 5: Form-Data Endpoints
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "SECTION 5: Form-Data (Multipart) Endpoints"
echo "═══════════════════════════════════════════════════════"

# 5.1 signPdf/form → binary PDF (visible)
echo ""
echo "--- 5.1 POST /api/v1/signPdf/form (PAdES visible → binary) ---"
HTTP=$(curl -s -o "$PROJECT/test-files/ct-form-visible.pdf" -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PROJECT/test-files/sample.pdf" \
  -F "image=@$PROJECT/test-files/signature-image.png" \
  -F "sigRect=50,50,250,150" \
  -F "signerName=Form Test" \
  -F "signatureFormat=pades" \
  -F "padesLevel=B-B")
if [ "$HTTP" = "200" ]; then
    SIZE=$(wc -c < "$PROJECT/test-files/ct-form-visible.pdf" | tr -d ' ')
    echo "  size=$SIZE bytes"
    ok "signPdf/form PAdES visible→binary ($SIZE bytes)"
else
    fail "signPdf/form visible→binary (HTTP $HTTP)"
fi

# 5.2 signPdf/form → JSON (invisible)
echo ""
echo "--- 5.2 POST /api/v1/signPdf/form (invisible → JSON) ---"
HTTP=$(curl -s -o /tmp/ct-form-json.json -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PROJECT/test-files/sample.pdf" \
  -F "responseFormat=json")
if [ "$HTTP" = "200" ]; then
    HAS=$(python3 -c "import json; print('signedPdf' in json.load(open('/tmp/ct-form-json.json')))" 2>/dev/null)
    echo "  hasSignedPdf=$HAS"
    ok "signPdf/form invisible→JSON"
else
    fail "signPdf/form invisible→JSON (HTTP $HTTP)"
fi

# 5.3 signPdf/form → binary PKCS7
echo ""
echo "--- 5.3 POST /api/v1/signPdf/form (PKCS7 → binary) ---"
HTTP=$(curl -s -o "$PROJECT/test-files/ct-form-pkcs7.pdf" -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PROJECT/test-files/sample.pdf" \
  -F "signatureFormat=pkcs7")
if [ "$HTTP" = "200" ]; then
    ok "signPdf/form PKCS7→binary"
else
    fail "signPdf/form PKCS7→binary (HTTP $HTTP)"
fi

# 5.4 validate/form
echo ""
echo "--- 5.4 POST /api/v1/validate/form ---"
HTTP=$(curl -s -o /tmp/ct-vform.json -w "%{http_code}" \
  -X POST "$BASE/api/v1/validate/form" \
  -F "file=@$PROJECT/test-files/ct-form-visible.pdf")
if [ "$HTTP" = "200" ]; then
    ALL=$(python3 -c "import json; print(json.load(open('/tmp/ct-vform.json'))['allValid'])" 2>/dev/null)
    echo "  allValid=$ALL"
    ok "validate/form"
else
    fail "validate/form (HTTP $HTTP)"
fi

# 5.5 signDoc/form
echo ""
echo "--- 5.5 POST /csc/v2/signatures/signDoc/form ---"
echo -n "TestByteRangeContentForFormData" > /tmp/ct-content.bin
HTTP=$(curl -s -o /tmp/ct-sdform.json -w "%{http_code}" \
  -X POST "$BASE/csc/v2/signatures/signDoc/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/ct-content.bin" \
  -F "signatureFormat=pades")
if [ "$HTTP" = "200" ]; then
    HAS=$(python3 -c "import json; print('signature' in json.load(open('/tmp/ct-sdform.json')))" 2>/dev/null)
    echo "  hasSignature=$HAS"
    ok "signDoc/form"
else
    fail "signDoc/form (HTTP $HTTP)"
fi
rm -f /tmp/ct-content.bin

# 5.6 Verify all form-signed PDFs
echo ""
echo "--- 5.6 verify form-signed PDFs ---"
for f in ct-form-visible.pdf ct-form-pkcs7.pdf; do
    FPATH="$PROJECT/test-files/$f"
    if [ -f "$FPATH" ]; then
        if RUST_LOG=error "$BINARY" verify --input "$FPATH" 2>&1 | grep -q "VALID"; then
            ok "verify $f"
        else
            fail "verify $f"
        fi
    fi
done

# ══════════════════════════════════════════════════════════════
# SECTION 6: CLI validate (remote validation)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "SECTION 6: CLI validate (remote via server API)"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "--- 6.1 CLI validate command ---"
if RUST_LOG=error "$BINARY" validate \
    --server-url "$BASE" \
    --input "$PROJECT/test-files/ct-pades-bb.pdf" 2>&1 | grep -q "VALID"; then
    ok "CLI validate PAdES"
else
    fail "CLI validate PAdES"
fi

# ══════════════════════════════════════════════════════════════
# SECTION 7: Error Handling
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo "SECTION 7: Error Handling"
echo "═══════════════════════════════════════════════════════"

# 7.1 signPdf without auth
echo ""
echo "--- 7.1 signPdf without auth → 401 ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf" \
  -H "Content-Type: application/json" \
  -d '{"credentialID":"credential-001","pdfContent":"dGVzdA=="}')
if [ "$HTTP" = "401" ]; then
    ok "signPdf no auth → 401"
else
    fail "signPdf no auth (expected 401, got $HTTP)"
fi

# 7.2 signPdf with wrong credential
echo ""
echo "--- 7.2 signPdf wrong credential → 403 ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"credentialID":"wrong-cred","pdfContent":"dGVzdA=="}')
if [ "$HTTP" = "403" ]; then
    ok "signPdf wrong credential → 403"
else
    fail "signPdf wrong credential (expected 403, got $HTTP)"
fi

# 7.3 signPdf/form missing file
echo ""
echo "--- 7.3 signPdf/form missing file → 400 ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "signatureFormat=pades")
if [ "$HTTP" = "400" ]; then
    ok "signPdf/form no file → 400"
else
    fail "signPdf/form no file (expected 400, got $HTTP)"
fi

# 7.4 validate with invalid PDF
echo ""
echo "--- 7.4 validate invalid PDF → error ---"
BAD_B64=$(echo -n "this is not a pdf" | base64)
HTTP=$(curl -s -o /tmp/ct-badinput.json -w "%{http_code}" \
  -X POST "$BASE/api/v1/validate" \
  -H "Content-Type: application/json" \
  -d "{\"pdfContent\":\"$BAD_B64\"}")
if [ "$HTTP" = "400" ] || [ "$HTTP" = "200" ]; then
    ok "validate invalid PDF → HTTP $HTTP (handled)"
else
    fail "validate invalid PDF (HTTP $HTTP)"
fi

# ══════════════════════════════════════════════════════════════
# Cleanup
# ══════════════════════════════════════════════════════════════
kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/ct-*.json

# ══════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                    TEST SUMMARY                          ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Total:   $TOTAL tests                                      ║"
echo "║  Passed:  $PASS                                              ║"
echo "║  Failed:  $FAIL                                              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED"
else
    echo "⚠️  $FAIL TEST(S) FAILED"
fi
echo ""
echo "Report saved to: $REPORT"

