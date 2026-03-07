#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Comprehensive endpoint test for remote-signature-pdf server
# Tests all 7 endpoints with positive AND negative cases
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

PROJECT_DIR="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BINARY="$PROJECT_DIR/target/debug/remote-signature-pdf"
REPORT="$PROJECT_DIR/test-files/endpoint-test-report.txt"
BASE="http://localhost:9090"
CERT_DIR="$PROJECT_DIR/certs"
PDF_FILE="$PROJECT_DIR/test-files/sample.pdf"

PASS_COUNT=0
FAIL_COUNT=0
TEST_NUM=0

# ── Helper functions ──

begin_report() {
    cat > "$REPORT" <<EOF
═══════════════════════════════════════════════════════════════════════════
  ENDPOINT TEST REPORT
  remote-signature-pdf server
  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
═══════════════════════════════════════════════════════════════════════════

EOF
}

log_test() {
    TEST_NUM=$((TEST_NUM + 1))
    local test_name="$1"
    local endpoint="$2"
    local status_code="$3"
    local expected="$4"
    local body_snippet="$5"
    local pass_fail=""

    if [ "$status_code" = "$expected" ]; then
        pass_fail="✅ PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        pass_fail="❌ FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    cat >> "$REPORT" <<EOF
───────────────────────────────────────────────────────────────────────────
TEST #$TEST_NUM: $test_name
  Endpoint:       $endpoint
  Expected HTTP:  $expected
  Actual HTTP:    $status_code
  Result:         $pass_fail
  Response:       $body_snippet
EOF
    echo "  [$pass_fail] #$TEST_NUM $test_name (HTTP $status_code)"
}

summary() {
    local total=$((PASS_COUNT + FAIL_COUNT))
    cat >> "$REPORT" <<EOF

═══════════════════════════════════════════════════════════════════════════
  SUMMARY
═══════════════════════════════════════════════════════════════════════════
  Total:    $total
  Passed:   $PASS_COUNT
  Failed:   $FAIL_COUNT
  Result:   $([ "$FAIL_COUNT" -eq 0 ] && echo "ALL PASSED ✅" || echo "SOME FAILED ❌")
═══════════════════════════════════════════════════════════════════════════
EOF
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  Total: $total  Passed: $PASS_COUNT  Failed: $FAIL_COUNT"
    echo "═══════════════════════════════════════════════════"
}

# Curl helper: returns "HTTP_CODE|BODY"
do_curl() {
    local method="$1"
    shift
    # remaining args are passed to curl
    curl -s -w "\n%{http_code}" -X "$method" "$@" 2>/dev/null || echo -e "\n000"
}

parse_response() {
    local raw="$1"
    HTTP_CODE=$(echo "$raw" | tail -1)
    BODY=$(echo "$raw" | sed '$d')
}

snippet() {
    # Truncate body to max 200 chars for the report
    echo "$1" | head -c 200
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

echo "Building project..."
cd "$PROJECT_DIR"
cargo build 2>/dev/null

echo "Starting server on port 9090..."
RUST_LOG=warn "$BINARY" server --cert-dir "$CERT_DIR" --port 9090 &
SERVER_PID=$!
sleep 3

# Verify server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "Server started (PID=$SERVER_PID)"
echo ""

begin_report

trap 'kill $SERVER_PID 2>/dev/null; exit' EXIT INT TERM

# ═══════════════════════════════════════════════════════════════════════════════
# 1. POST /csc/v2/info
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /csc/v2/info ───"

# 1a. Normal request
RAW=$(do_curl POST "$BASE/csc/v2/info" -H "Content-Type: application/json" -d '{}')
parse_response "$RAW"
log_test "Info — normal request" "POST /csc/v2/info" "$HTTP_CODE" "200" "$(snippet "$BODY")"

# 1b. Verify response contains expected fields
HAS_FORMATS=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if 'signatureFormats' in d and 'padesLevels' in d else 'missing')" 2>/dev/null || echo "parse_error")
if [ "$HAS_FORMATS" = "ok" ]; then
    log_test "Info — has signatureFormats & padesLevels" "POST /csc/v2/info" "200" "200" "Fields present: signatureFormats, padesLevels"
else
    log_test "Info — has signatureFormats & padesLevels" "POST /csc/v2/info" "MISSING" "200" "$HAS_FORMATS"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 2. POST /csc/v2/auth/login
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /csc/v2/auth/login ───"

# 2a. Valid login (testuser/testpass)
BASIC_AUTH=$(echo -n "testuser:testpass" | base64)
RAW=$(do_curl POST "$BASE/csc/v2/auth/login" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $BASIC_AUTH" \
    -d '{"rememberMe": false}')
parse_response "$RAW"
log_test "Auth — valid credentials (testuser)" "POST /csc/v2/auth/login" "$HTTP_CODE" "200" "$(snippet "$BODY")"
TOKEN=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

# 2b. Valid login (signer/signer123)
BASIC_AUTH2=$(echo -n "signer:signer123" | base64)
RAW=$(do_curl POST "$BASE/csc/v2/auth/login" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $BASIC_AUTH2" \
    -d '{"rememberMe": false}')
parse_response "$RAW"
log_test "Auth — valid credentials (signer)" "POST /csc/v2/auth/login" "$HTTP_CODE" "200" "$(snippet "$BODY")"

# 2c. Invalid password
BASIC_BAD=$(echo -n "testuser:wrongpass" | base64)
RAW=$(do_curl POST "$BASE/csc/v2/auth/login" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $BASIC_BAD" \
    -d '{"rememberMe": false}')
parse_response "$RAW"
log_test "Auth — invalid password" "POST /csc/v2/auth/login" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# 2d. Missing auth header
RAW=$(do_curl POST "$BASE/csc/v2/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"rememberMe": false}')
parse_response "$RAW"
log_test "Auth — missing auth header" "POST /csc/v2/auth/login" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# 2e. Invalid user
BASIC_NOUSER=$(echo -n "nobody:nopass" | base64)
RAW=$(do_curl POST "$BASE/csc/v2/auth/login" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $BASIC_NOUSER" \
    -d '{"rememberMe": false}')
parse_response "$RAW"
log_test "Auth — unknown user" "POST /csc/v2/auth/login" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# ═══════════════════════════════════════════════════════════════════════════════
# 3. POST /csc/v2/credentials/list
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /csc/v2/credentials/list ───"

# 3a. Valid request with token
RAW=$(do_curl POST "$BASE/csc/v2/credentials/list" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{}')
parse_response "$RAW"
log_test "Credentials/list — valid token" "POST /csc/v2/credentials/list" "$HTTP_CODE" "200" "$(snippet "$BODY")"

# 3b. No token
RAW=$(do_curl POST "$BASE/csc/v2/credentials/list" \
    -H "Content-Type: application/json" \
    -d '{}')
parse_response "$RAW"
log_test "Credentials/list — no token" "POST /csc/v2/credentials/list" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# 3c. Invalid token
RAW=$(do_curl POST "$BASE/csc/v2/credentials/list" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer invalid.token.here" \
    -d '{}')
parse_response "$RAW"
log_test "Credentials/list — invalid token" "POST /csc/v2/credentials/list" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# ═══════════════════════════════════════════════════════════════════════════════
# 4. POST /csc/v2/credentials/info
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /csc/v2/credentials/info ───"

# 4a. Valid request — single cert
RAW=$(do_curl POST "$BASE/csc/v2/credentials/info" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"credentialID":"credential-001","certificates":"single"}')
parse_response "$RAW"
log_test "Credentials/info — single cert" "POST /csc/v2/credentials/info" "$HTTP_CODE" "200" "$(snippet "$BODY")"

# 4b. Valid request — chain
RAW=$(do_curl POST "$BASE/csc/v2/credentials/info" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"credentialID":"credential-001","certificates":"chain"}')
parse_response "$RAW"
log_test "Credentials/info — cert chain" "POST /csc/v2/credentials/info" "$HTTP_CODE" "200" "$(snippet "$BODY")"
CERT_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['cert']['certificates']))" 2>/dev/null || echo "0")
if [ "$CERT_COUNT" -ge 2 ]; then
    log_test "Credentials/info — chain has >=2 certs" "POST /csc/v2/credentials/info" "200" "200" "Chain contains $CERT_COUNT certificate(s)"
else
    log_test "Credentials/info — chain has >=2 certs" "POST /csc/v2/credentials/info" "FAIL" "200" "Only $CERT_COUNT cert(s) in chain"
fi

# 4c. Invalid credential ID
RAW=$(do_curl POST "$BASE/csc/v2/credentials/info" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"credentialID":"nonexistent-cred","certificates":"single"}')
parse_response "$RAW"
log_test "Credentials/info — invalid credential ID" "POST /csc/v2/credentials/info" "$HTTP_CODE" "404" "$(snippet "$BODY")"

# 4d. No token
RAW=$(do_curl POST "$BASE/csc/v2/credentials/info" \
    -H "Content-Type: application/json" \
    -d '{"credentialID":"credential-001","certificates":"single"}')
parse_response "$RAW"
log_test "Credentials/info — no token" "POST /csc/v2/credentials/info" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# ═══════════════════════════════════════════════════════════════════════════════
# 5. POST /csc/v2/signatures/signHash
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /csc/v2/signatures/signHash ───"

# Generate a test SHA-256 hash (hash of "hello world")
TEST_HASH=$(echo -n "hello world" | shasum -a 256 | cut -d' ' -f1)
TEST_HASH_B64=$(echo -n "$TEST_HASH" | xxd -r -p | base64)

# 5a. Valid signHash
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signHash" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"hashes\":[\"$TEST_HASH_B64\"],\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\"}")
parse_response "$RAW"
log_test "SignHash — valid request" "POST /csc/v2/signatures/signHash" "$HTTP_CODE" "200" "$(snippet "$BODY")"

# 5b. Empty hashes array
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signHash" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"credentialID":"credential-001","hashes":[],"hashAlgo":"2.16.840.1.101.3.4.2.1","signAlgo":"1.2.840.113549.1.1.11"}')
parse_response "$RAW"
log_test "SignHash — empty hashes" "POST /csc/v2/signatures/signHash" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# 5c. Unsupported hash algo
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signHash" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"hashes\":[\"$TEST_HASH_B64\"],\"hashAlgo\":\"1.2.3.4.5.6.7\",\"signAlgo\":\"1.2.840.113549.1.1.11\"}")
parse_response "$RAW"
log_test "SignHash — unsupported hashAlgo" "POST /csc/v2/signatures/signHash" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# 5d. No token
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signHash" \
    -H "Content-Type: application/json" \
    -d "{\"credentialID\":\"credential-001\",\"hashes\":[\"$TEST_HASH_B64\"],\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\"}")
parse_response "$RAW"
log_test "SignHash — no token" "POST /csc/v2/signatures/signHash" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# 5e. Invalid hash (wrong length)
BAD_HASH_B64=$(echo -n "too_short" | base64)
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signHash" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"hashes\":[\"$BAD_HASH_B64\"],\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\"}")
parse_response "$RAW"
log_test "SignHash — wrong hash length" "POST /csc/v2/signatures/signHash" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# ═══════════════════════════════════════════════════════════════════════════════
# 6. POST /csc/v2/signatures/signDoc
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /csc/v2/signatures/signDoc ───"

# Prepare test document content (small payload)
DOC_CONTENT_B64=$(echo -n "test document content for signing" | base64)

# 6a. signDoc — PAdES B-B
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_CONTENT_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-B\"}")
parse_response "$RAW"
log_test "SignDoc — PAdES B-B" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "200" "$(snippet "$BODY")"
# Verify response has signature field
SIG_FORMAT=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('signatureFormat',''))" 2>/dev/null || echo "")
PADES_LVL=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('padesLevel',''))" 2>/dev/null || echo "")
if [ "$SIG_FORMAT" = "pades" ] && [ "$PADES_LVL" = "B-B" ]; then
    log_test "SignDoc — B-B response format correct" "POST /csc/v2/signatures/signDoc" "200" "200" "format=pades, level=B-B"
else
    log_test "SignDoc — B-B response format correct" "POST /csc/v2/signatures/signDoc" "FAIL" "200" "format=$SIG_FORMAT, level=$PADES_LVL"
fi

# 6b. signDoc — PAdES B-T (no TSA URL, should still work but no timestamp)
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_CONTENT_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-T\"}")
parse_response "$RAW"
log_test "SignDoc — PAdES B-T (no TSA)" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "200" "$(snippet "$BODY")"

# 6c. signDoc — PKCS7
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_CONTENT_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pkcs7\"}")
parse_response "$RAW"
log_test "SignDoc — PKCS7 format" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "200" "$(snippet "$BODY")"
SIG_FORMAT=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('signatureFormat',''))" 2>/dev/null || echo "")
if [ "$SIG_FORMAT" = "pkcs7" ]; then
    log_test "SignDoc — PKCS7 response format correct" "POST /csc/v2/signatures/signDoc" "200" "200" "format=pkcs7"
else
    log_test "SignDoc — PKCS7 response format correct" "POST /csc/v2/signatures/signDoc" "FAIL" "200" "format=$SIG_FORMAT"
fi

# 6d. signDoc — Invalid hashAlgo
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_CONTENT_B64\",\"hashAlgo\":\"9.9.9.9\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-B\"}")
parse_response "$RAW"
log_test "SignDoc — unsupported hashAlgo" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# 6e. signDoc — No token
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -d "{\"credentialID\":\"credential-001\",\"documentContent\":\"$DOC_CONTENT_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-B\"}")
parse_response "$RAW"
log_test "SignDoc — no token" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "401" "$(snippet "$BODY")"

# 6f. signDoc — Invalid base64 content
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"credentialID":"credential-001","documentContent":"!!!not-base64!!!","hashAlgo":"2.16.840.1.101.3.4.2.1","signAlgo":"1.2.840.113549.1.1.11","signatureFormat":"pades","padesLevel":"B-B"}')
parse_response "$RAW"
log_test "SignDoc — invalid base64 content" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# 6g. signDoc — Wrong credential ID
RAW=$(do_curl POST "$BASE/csc/v2/signatures/signDoc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"credentialID\":\"wrong-cred-99\",\"documentContent\":\"$DOC_CONTENT_B64\",\"hashAlgo\":\"2.16.840.1.101.3.4.2.1\",\"signAlgo\":\"1.2.840.113549.1.1.11\",\"signatureFormat\":\"pades\",\"padesLevel\":\"B-B\"}")
parse_response "$RAW"
log_test "SignDoc — wrong credential ID" "POST /csc/v2/signatures/signDoc" "$HTTP_CODE" "403" "$(snippet "$BODY")"

# ═══════════════════════════════════════════════════════════════════════════════
# 7. POST /api/v1/validate
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing /api/v1/validate ───"

# First, do a real sign to produce a valid signed PDF for validation
RUST_LOG=error "$BINARY" sign \
    --server-url "$BASE" \
    --input "$PDF_FILE" \
    --output "$PROJECT_DIR/test-files/test-signed-for-validate.pdf" \
    --format pades --level B-B 2>/dev/null

SIGNED_PDF_B64=$(base64 < "$PROJECT_DIR/test-files/test-signed-for-validate.pdf")

# 7a. Validate — valid signed PDF
RAW=$(do_curl POST "$BASE/api/v1/validate" \
    -H "Content-Type: application/json" \
    -d "{\"pdfContent\":\"$SIGNED_PDF_B64\"}")
parse_response "$RAW"
log_test "Validate — valid signed PDF" "POST /api/v1/validate" "$HTTP_CODE" "200" "$(snippet "$BODY")"
# Check response fields
ALL_VALID=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('allValid') else 'false')" 2>/dev/null || echo "unknown")
SIG_COUNT=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('signatureCount',0))" 2>/dev/null || echo "0")
if [ "$ALL_VALID" = "true" ] && [ "$SIG_COUNT" -ge 1 ]; then
    log_test "Validate — allValid=true, signatureCount>=1" "POST /api/v1/validate" "200" "200" "allValid=$ALL_VALID, signatureCount=$SIG_COUNT"
else
    log_test "Validate — allValid=true, signatureCount>=1" "POST /api/v1/validate" "FAIL" "200" "allValid=$ALL_VALID, signatureCount=$SIG_COUNT"
fi

# 7b. Validate — check detailed signature fields
HAS_DETAILS=$(echo "$BODY" | python3 -c "
import sys,json
d=json.load(sys.stdin)
sig=d['signatures'][0]
fields=['digestMatch','cmsSignatureValid','certificateChainValid','byteRangeValid',
        'hasDss','hasTimestamp','isLtvEnabled','signatureNotWrapped',
        'noUnauthorizedModifications','certificationPermissionOk']
missing = [f for f in fields if f not in sig]
print('ok' if not missing else 'missing: ' + ','.join(missing))
" 2>/dev/null || echo "parse_error")
if [ "$HAS_DETAILS" = "ok" ]; then
    log_test "Validate — response has all validation fields" "POST /api/v1/validate" "200" "200" "All validation fields present"
else
    log_test "Validate — response has all validation fields" "POST /api/v1/validate" "FAIL" "200" "$HAS_DETAILS"
fi

# 7c. Validate — unsigned PDF
UNSIGNED_PDF_B64=$(base64 < "$PDF_FILE")
RAW=$(do_curl POST "$BASE/api/v1/validate" \
    -H "Content-Type: application/json" \
    -d "{\"pdfContent\":\"$UNSIGNED_PDF_B64\"}")
parse_response "$RAW"
# Expect 200 with signatureCount=0 OR 400 with error message
EXPECTED_CODE="200"
SIG_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signatureCount','-'))" 2>/dev/null || echo "-")
if [ "$HTTP_CODE" = "200" ] && [ "$SIG_COUNT" = "0" ]; then
    log_test "Validate — unsigned PDF" "POST /api/v1/validate" "$HTTP_CODE" "200" "signatureCount=0 (correct)"
elif [ "$HTTP_CODE" = "400" ]; then
    log_test "Validate — unsigned PDF" "POST /api/v1/validate" "$HTTP_CODE" "400" "$(snippet "$BODY")"
    # This is also acceptable
    FAIL_COUNT=$((FAIL_COUNT - 1))
    PASS_COUNT=$((PASS_COUNT + 1))
else
    log_test "Validate — unsigned PDF" "POST /api/v1/validate" "$HTTP_CODE" "200" "$(snippet "$BODY")"
fi

# 7d. Validate — invalid base64
RAW=$(do_curl POST "$BASE/api/v1/validate" \
    -H "Content-Type: application/json" \
    -d '{"pdfContent":"!!!not-valid-base64!!!"}')
parse_response "$RAW"
log_test "Validate — invalid base64" "POST /api/v1/validate" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# 7e. Validate — corrupt/non-PDF bytes
GARBAGE_B64=$(echo -n "this is not a pdf file at all" | base64)
RAW=$(do_curl POST "$BASE/api/v1/validate" \
    -H "Content-Type: application/json" \
    -d "{\"pdfContent\":\"$GARBAGE_B64\"}")
parse_response "$RAW"
log_test "Validate — non-PDF content" "POST /api/v1/validate" "$HTTP_CODE" "400" "$(snippet "$BODY")"

# 7f. Validate PKCS7-signed PDF
RUST_LOG=error "$BINARY" sign \
    --server-url "$BASE" \
    --input "$PDF_FILE" \
    --output "$PROJECT_DIR/test-files/test-signed-pkcs7-validate.pdf" \
    --format pkcs7 2>/dev/null
PKCS7_PDF_B64=$(base64 < "$PROJECT_DIR/test-files/test-signed-pkcs7-validate.pdf")
RAW=$(do_curl POST "$BASE/api/v1/validate" \
    -H "Content-Type: application/json" \
    -d "{\"pdfContent\":\"$PKCS7_PDF_B64\"}")
parse_response "$RAW"
log_test "Validate — PKCS7-signed PDF" "POST /api/v1/validate" "$HTTP_CODE" "200" "$(snippet "$BODY")"
ALL_VALID=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('allValid') else 'false')" 2>/dev/null || echo "unknown")
if [ "$ALL_VALID" = "true" ]; then
    log_test "Validate — PKCS7 allValid=true" "POST /api/v1/validate" "200" "200" "PKCS7 signature validated successfully"
else
    log_test "Validate — PKCS7 allValid=true" "POST /api/v1/validate" "FAIL" "200" "allValid=$ALL_VALID"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 8. E2E: Full signing + validation workflow
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing E2E workflow ───"

# 8a. Full PAdES B-B sign → validate via API
E2E_PDF_B64=$(base64 < "$PROJECT_DIR/test-files/test-signed-for-validate.pdf")
RAW=$(do_curl POST "$BASE/api/v1/validate" \
    -H "Content-Type: application/json" \
    -d "{\"pdfContent\":\"$E2E_PDF_B64\"}")
parse_response "$RAW"
E2E_VALID=$(echo "$BODY" | python3 -c "
import sys,json
d=json.load(sys.stdin)
sig=d['signatures'][0]
print('true' if sig['digestMatch'] and sig['cmsSignatureValid'] and sig['certificateChainValid'] and sig['byteRangeValid'] else 'false')
" 2>/dev/null || echo "false")
if [ "$E2E_VALID" = "true" ]; then
    log_test "E2E — sign PAdES B-B then validate via API" "full workflow" "200" "200" "All crypto checks passed"
else
    log_test "E2E — sign PAdES B-B then validate via API" "full workflow" "FAIL" "200" "Some checks failed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 9. Edge cases / misc
# ═══════════════════════════════════════════════════════════════════════════════
echo "─── Testing edge cases ───"

# 9a. Wrong HTTP method (GET instead of POST)
RAW=$(do_curl GET "$BASE/csc/v2/info")
parse_response "$RAW"
# Actix returns 404 for unmatched methods (not 405); both are acceptable
if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "405" ]; then
    log_test "Edge — GET /csc/v2/info (should reject)" "GET /csc/v2/info" "$HTTP_CODE" "$HTTP_CODE" "Correctly rejected GET request"
else
    log_test "Edge — GET /csc/v2/info (should reject)" "GET /csc/v2/info" "$HTTP_CODE" "405" "$(snippet "$BODY")"
fi

# 9b. Non-existent endpoint
RAW=$(do_curl POST "$BASE/csc/v2/nonexistent" \
    -H "Content-Type: application/json" \
    -d '{}')
parse_response "$RAW"
log_test "Edge — non-existent endpoint" "POST /csc/v2/nonexistent" "$HTTP_CODE" "404" "$(snippet "$BODY")"

# 9c. Missing Content-Type
RAW=$(do_curl POST "$BASE/csc/v2/info" -d '{}')
parse_response "$RAW"
# Actix may accept or reject this — just record the result
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "415" ]; then
    log_test "Edge — missing Content-Type on /info" "POST /csc/v2/info" "$HTTP_CODE" "$HTTP_CODE" "$(snippet "$BODY")"
else
    log_test "Edge — missing Content-Type on /info" "POST /csc/v2/info" "$HTTP_CODE" "200" "$(snippet "$BODY")"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Done — write summary
# ═══════════════════════════════════════════════════════════════════════════════

summary

# Cleanup temp files
rm -f "$PROJECT_DIR/test-files/test-signed-for-validate.pdf" \
      "$PROJECT_DIR/test-files/test-signed-pkcs7-validate.pdf"

echo ""
echo "Report saved to: $REPORT"

