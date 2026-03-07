#!/bin/bash
set -euo pipefail

PROJECT="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BINARY="$PROJECT/target/debug/remote-signature-pdf"
PORT=9092
LOG="$PROJECT/test-files/visible-sig-test.log"

exec > "$LOG" 2>&1

echo "=== Visible Signature Test ==="
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

# Check server
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "Server started (PID=$SERVER_PID)"

# Test 1: Sign with visible signature (PAdES B-B)
echo ""
echo "--- Test 1: Sign with visible signature image (PAdES B-B) ---"
RUST_LOG=info "$BINARY" sign \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-visible.pdf" \
  --format pades --level B-B \
  --image "$PROJECT/test-files/signature-image.png" \
  --sig-page 1 \
  --sig-rect "50,50,250,150" && echo "SIGN_1=OK" || echo "SIGN_1=FAIL"

# Test 2: Sign with visible signature (PKCS7)
echo ""
echo "--- Test 2: Sign with visible signature image (PKCS7) ---"
RUST_LOG=info "$BINARY" sign \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-visible-pkcs7.pdf" \
  --format pkcs7 \
  --image "$PROJECT/test-files/signature-image.png" \
  --sig-page 1 \
  --sig-rect "300,600,500,700" && echo "SIGN_2=OK" || echo "SIGN_2=FAIL"

# Test 3: Sign without image (invisible, control test)
echo ""
echo "--- Test 3: Sign without image (invisible, control) ---"
RUST_LOG=info "$BINARY" sign \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-invisible-ctrl.pdf" \
  --format pades --level B-B && echo "SIGN_3=OK" || echo "SIGN_3=FAIL"

# Verify each signed PDF
echo ""
echo "--- Verifying signed PDFs ---"

for f in "$PROJECT/test-files/signed-visible.pdf" \
         "$PROJECT/test-files/signed-visible-pkcs7.pdf" \
         "$PROJECT/test-files/signed-invisible-ctrl.pdf"; do
    if [ -f "$f" ]; then
        echo ""
        echo "Verifying: $f"
        RUST_LOG=error "$BINARY" verify --input "$f" && echo "VERIFY=OK" || echo "VERIFY=FAIL"
    else
        echo "MISSING: $f"
    fi
done

# List output files
echo ""
echo "--- Output files ---"
ls -la "$PROJECT/test-files/signed-visible"*.pdf 2>/dev/null || echo "(no visible files)"
ls -la "$PROJECT/test-files/signed-invisible-ctrl.pdf" 2>/dev/null || echo "(no invisible file)"

# Kill server
kill $SERVER_PID 2>/dev/null || true
echo ""
echo "=== Test complete ==="

