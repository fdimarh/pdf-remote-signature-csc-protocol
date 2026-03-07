#!/bin/bash
# Test form-data (multipart) endpoints
set -euo pipefail

PROJECT="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BINARY="$PROJECT/target/debug/remote-signature-pdf"
PORT=9095
LOG="$PROJECT/test-files/form-data-test.log"

exec > "$LOG" 2>&1

echo "=== Form-Data Endpoint Tests ==="
echo "Date: $(date)"
echo ""

# Kill previous servers
pkill -f "remote-signature-pdf server" 2>/dev/null || true
sleep 2

# Start server
echo "Starting server on port $PORT..."
RUST_LOG=info "$BINARY" server --port $PORT &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "Server started (PID=$SERVER_PID)"

# Login to get token
echo ""
echo "--- Login ---"
TOKEN=$(curl -s -X POST "http://localhost:$PORT/csc/v2/auth/login" \
  -H "Authorization: Basic $(echo -n testuser:testpass | base64)" \
  -H "Content-Type: application/json" \
  -d '{"rememberMe": true}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
echo "Token: ${TOKEN:0:20}..."

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local result="$2"
    if [ "$result" = "PASS" ]; then
        PASS=$((PASS+1))
        echo "  ✅ $name: PASS"
    else
        FAIL=$((FAIL+1))
        echo "  ❌ $name: FAIL"
    fi
}

# ═══════════════════════════════════════════════════════════
# Test 1: POST /api/v1/signPdf/form — binary response (with visible image)
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 1: signPdf/form (PAdES + visible image) → binary PDF ---"
HTTP_CODE=$(curl -s -o "$PROJECT/test-files/signed-form-visible.pdf" -w "%{http_code}" \
  -X POST "http://localhost:$PORT/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PROJECT/test-files/sample.pdf" \
  -F "image=@$PROJECT/test-files/signature-image.png" \
  -F "sigRect=50,50,250,150" \
  -F "signerName=Form-Data Signer" \
  -F "signatureFormat=pades" \
  -F "padesLevel=B-B")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    SIZE=$(wc -c < "$PROJECT/test-files/signed-form-visible.pdf" | tr -d ' ')
    echo "Output: $SIZE bytes"
    run_test "signPdf/form PAdES+visible→binary" "PASS"
else
    run_test "signPdf/form PAdES+visible→binary" "FAIL"
fi

# ═══════════════════════════════════════════════════════════
# Test 2: POST /api/v1/signPdf/form — JSON response (invisible)
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 2: signPdf/form (PAdES invisible) → JSON ---"
HTTP_CODE=$(curl -s -o /tmp/form-test2.json -w "%{http_code}" \
  -X POST "http://localhost:$PORT/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PROJECT/test-files/sample.pdf" \
  -F "signatureFormat=pades" \
  -F "padesLevel=B-B" \
  -F "responseFormat=json")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    HAS_PDF=$(python3 -c "import json; d=json.load(open('/tmp/form-test2.json')); print('signedPdf' in d)" 2>/dev/null || echo "false")
    FMT=$(python3 -c "import json; print(json.load(open('/tmp/form-test2.json')).get('signatureFormat',''))" 2>/dev/null || echo "unknown")
    echo "has_signedPdf=$HAS_PDF, format=$FMT"
    run_test "signPdf/form PAdES invisible→JSON" "PASS"
else
    run_test "signPdf/form PAdES invisible→JSON" "FAIL"
fi

# ═══════════════════════════════════════════════════════════
# Test 3: POST /api/v1/signPdf/form — PKCS7 binary response
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 3: signPdf/form (PKCS7 invisible) → binary PDF ---"
HTTP_CODE=$(curl -s -o "$PROJECT/test-files/signed-form-pkcs7.pdf" -w "%{http_code}" \
  -X POST "http://localhost:$PORT/api/v1/signPdf/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PROJECT/test-files/sample.pdf" \
  -F "signatureFormat=pkcs7")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    SIZE=$(wc -c < "$PROJECT/test-files/signed-form-pkcs7.pdf" | tr -d ' ')
    echo "Output: $SIZE bytes"
    run_test "signPdf/form PKCS7→binary" "PASS"
else
    run_test "signPdf/form PKCS7→binary" "FAIL"
fi

# ═══════════════════════════════════════════════════════════
# Test 4: POST /api/v1/validate/form — validate PAdES signed PDF
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 4: validate/form (PAdES signed PDF) ---"
HTTP_CODE=$(curl -s -o /tmp/form-test4.json -w "%{http_code}" \
  -X POST "http://localhost:$PORT/api/v1/validate/form" \
  -F "file=@$PROJECT/test-files/signed-form-visible.pdf")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    ALL_VALID=$(python3 -c "import json; print(json.load(open('/tmp/form-test4.json')).get('allValid',''))" 2>/dev/null || echo "unknown")
    SIG_COUNT=$(python3 -c "import json; print(json.load(open('/tmp/form-test4.json')).get('signatureCount',''))" 2>/dev/null || echo "unknown")
    echo "allValid=$ALL_VALID, signatureCount=$SIG_COUNT"
    run_test "validate/form PAdES" "PASS"
else
    run_test "validate/form PAdES" "FAIL"
fi

# ═══════════════════════════════════════════════════════════
# Test 5: POST /api/v1/validate/form — validate PKCS7 signed PDF
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 5: validate/form (PKCS7 signed PDF) ---"
HTTP_CODE=$(curl -s -o /tmp/form-test5.json -w "%{http_code}" \
  -X POST "http://localhost:$PORT/api/v1/validate/form" \
  -F "file=@$PROJECT/test-files/signed-form-pkcs7.pdf")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    ALL_VALID=$(python3 -c "import json; print(json.load(open('/tmp/form-test5.json')).get('allValid',''))" 2>/dev/null || echo "unknown")
    echo "allValid=$ALL_VALID"
    run_test "validate/form PKCS7" "PASS"
else
    run_test "validate/form PKCS7" "FAIL"
fi

# ═══════════════════════════════════════════════════════════
# Test 6: POST /csc/v2/signatures/signDoc/form — form-data signDoc
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 6: signDoc/form (byte-range content) → JSON ---"
echo -n "TestContent1234567890ABCDEF" > /tmp/test-content.bin
HTTP_CODE=$(curl -s -o /tmp/form-test6.json -w "%{http_code}" \
  -X POST "http://localhost:$PORT/csc/v2/signatures/signDoc/form" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/test-content.bin" \
  -F "signatureFormat=pades" \
  -F "padesLevel=B-B")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    HAS_SIG=$(python3 -c "import json; print('signature' in json.load(open('/tmp/form-test6.json')))" 2>/dev/null || echo "false")
    FMT=$(python3 -c "import json; print(json.load(open('/tmp/form-test6.json')).get('signatureFormat',''))" 2>/dev/null || echo "unknown")
    echo "has_signature=$HAS_SIG, format=$FMT"
    run_test "signDoc/form→JSON" "PASS"
else
    cat /tmp/form-test6.json 2>/dev/null
    run_test "signDoc/form→JSON" "FAIL"
fi
rm -f /tmp/test-content.bin

# ═══════════════════════════════════════════════════════════
# Test 7: Local verify of form-signed PDFs
# ═══════════════════════════════════════════════════════════
echo ""
echo "--- Test 7: Local verify of form-signed PDFs ---"
for f in "$PROJECT/test-files/signed-form-visible.pdf" \
         "$PROJECT/test-files/signed-form-pkcs7.pdf"; do
    if [ -f "$f" ]; then
        FNAME=$(basename "$f")
        echo ""
        echo "Verifying: $FNAME"
        if RUST_LOG=error "$BINARY" verify --input "$f" 2>&1 | grep -q "VALID"; then
            run_test "verify $FNAME" "PASS"
        else
            run_test "verify $FNAME" "FAIL"
        fi
    fi
done

# Cleanup temp files
rm -f /tmp/form-test*.json

# Summary
echo ""
echo "═══════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed (total $((PASS+FAIL)))"
echo "═══════════════════════════════════════"

kill $SERVER_PID 2>/dev/null || true
echo ""
echo "=== Test complete ==="

