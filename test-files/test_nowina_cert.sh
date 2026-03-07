#!/bin/bash
set -euo pipefail

PROJECT="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BINARY="$PROJECT/target/debug/remote-signature-pdf"
PORT=9094
LOG="$PROJECT/test-files/nowina-cert-test.log"

exec > "$LOG" 2>&1

echo "=== Nowina Certificate Backend Test ==="
echo "Date: $(date)"
echo ""

# Kill any existing server
pkill -f "remote-signature-pdf server" 2>/dev/null || true
sleep 2

# Start server with Nowina certs (chain layout)
echo "Starting server on port $PORT with Nowina certs..."
RUST_LOG=info "$BINARY" server --cert-dir "$PROJECT/certs/nowina" --port $PORT &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "Server started (PID=$SERVER_PID)"

# Test 1: Get server info
echo ""
echo "--- Test 1: Server info ---"
curl -s -X POST "http://localhost:$PORT/csc/v2/info" \
  -H "Content-Type: application/json" -d '{}' | python3 -m json.tool 2>/dev/null || echo "(json format failed)"

# Test 2: Sign with PAdES B-B (client-side prep)
echo ""
echo "--- Test 2: Sign PAdES B-B (client-side prep) ---"
RUST_LOG=info "$BINARY" sign \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-nowina-pades.pdf" \
  --format pades --level B-B && echo "SIGN_PADES=PASS" || echo "SIGN_PADES=FAIL"

# Test 3: Sign with visible image (server-side)
echo ""
echo "--- Test 3: Sign server-side with visible image ---"
RUST_LOG=info "$BINARY" sign-remote \
  --server-url "http://localhost:$PORT" \
  --input "$PROJECT/test-files/sample.pdf" \
  --output "$PROJECT/test-files/signed-nowina-visible.pdf" \
  --image "$PROJECT/test-files/signature-image.png" \
  --sig-rect "50,50,250,150" \
  --signer-name "Nowina Test Signer" && echo "SIGN_VISIBLE=PASS" || echo "SIGN_VISIBLE=FAIL"

# Test 4: Verify signed PDFs
echo ""
echo "--- Test 4: Verify signed PDFs ---"

for f in "$PROJECT/test-files/signed-nowina-pades.pdf" \
         "$PROJECT/test-files/signed-nowina-visible.pdf"; do
    if [ -f "$f" ]; then
        echo ""
        echo "Verifying: $(basename $f)"
        RUST_LOG=error "$BINARY" verify --input "$f" && echo "VERIFY=PASS" || echo "VERIFY=FAIL"
    else
        echo "MISSING: $f"
    fi
done

# Test 5: Also verify the original self-signed cert still works
echo ""
echo "--- Test 5: Start server with original certs to verify backward compat ---"
kill $SERVER_PID 2>/dev/null || true
sleep 2

RUST_LOG=info "$BINARY" server --cert-dir "$PROJECT/certs" --port $PORT &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Legacy server failed to start"
else
    echo "Legacy server started (PID=$SERVER_PID)"
    RUST_LOG=info "$BINARY" sign \
      --server-url "http://localhost:$PORT" \
      --input "$PROJECT/test-files/sample.pdf" \
      --output "$PROJECT/test-files/signed-legacy-compat.pdf" \
      --format pades --level B-B && echo "LEGACY_COMPAT=PASS" || echo "LEGACY_COMPAT=FAIL"
fi

# Output files
echo ""
echo "--- Output files ---"
ls -la "$PROJECT/test-files/signed-nowina"*.pdf 2>/dev/null || echo "(no nowina files)"
ls -la "$PROJECT/test-files/signed-legacy-compat.pdf" 2>/dev/null || echo "(no legacy file)"

# Cleanup
kill $SERVER_PID 2>/dev/null || true
echo ""
echo "=== Test complete ==="

