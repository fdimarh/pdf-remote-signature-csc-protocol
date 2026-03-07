#!/bin/bash
set -euo pipefail

PROJECT="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BINARY="$PROJECT/target/debug/remote-signature-pdf"
PORT=9093
LOG="$PROJECT/test-files/server-side-sign-test.log"

exec > "$LOG" 2>&1

echo "=== Server-Side Sign PDF Test ==="
echo "Date: $(date)"
echo ""

# Kill any existing server
pkill -f "remote-signature-pdf server" 2>/dev/null || true
sleep 2

# Start server
echo "Starting server on port $PORT..."
RUST_LOG=info "$BINARY" server --cert-dir "$PROJECT/certs" --port $PORT &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "Server started (PID=$SERVER_PID)"

# Test 1: Server-side sign with visible signature (PAdES B-B)
echo ""
echo "--- Test 1: sign-remote with visible image (PAdES B-B) ---"
RUST_LOG=info "$BINARY" sign-remote \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-server-visible.pdf" \
  --format pades --level B-B \
  --image "$PROJECT/test-files/signature-image.png" \
  --sig-page 1 \
  --sig-rect "50,50,250,150" \
  --signer-name "Server-Side Signer" && echo "TEST_1=PASS" || echo "TEST_1=FAIL"

# Test 2: Server-side sign without image (invisible)
echo ""
echo "--- Test 2: sign-remote without image (invisible, PAdES B-B) ---"
RUST_LOG=info "$BINARY" sign-remote \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-server-invisible.pdf" \
  --format pades --level B-B && echo "TEST_2=PASS" || echo "TEST_2=FAIL"

# Test 3: Server-side sign with PKCS7 + visible
echo ""
echo "--- Test 3: sign-remote PKCS7 + visible image ---"
RUST_LOG=info "$BINARY" sign-remote \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-server-pkcs7.pdf" \
  --format pkcs7 \
  --image "$PROJECT/test-files/signature-image.png" \
  --sig-rect "300,600,500,700" && echo "TEST_3=PASS" || echo "TEST_3=FAIL"

# Verify each signed PDF
echo ""
echo "--- Verifying signed PDFs ---"

for f in "$PROJECT/test-files/signed-server-visible.pdf" \
         "$PROJECT/test-files/signed-server-invisible.pdf" \
         "$PROJECT/test-files/signed-server-pkcs7.pdf"; do
    if [ -f "$f" ]; then
        echo ""
        echo "Verifying: $(basename $f)"
        RUST_LOG=error "$BINARY" verify --input "$f" && echo "VERIFY=PASS" || echo "VERIFY=FAIL"
    else
        echo "MISSING: $f"
    fi
done

# List output files
echo ""
echo "--- Output files ---"
ls -la "$PROJECT/test-files/signed-server"*.pdf 2>/dev/null || echo "(no files)"

# Kill server
kill $SERVER_PID 2>/dev/null || true
echo ""
echo "=== Test complete ==="

