#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Comprehensive Signing & Validation Test Suite — with Performance Timing
# ═══════════════════════════════════════════════════════════════════════
# Tests ALL signing methods with per-test and per-section timing:
#   A.  Client-side signing  (CLI → CSC signDoc → embed locally)
#   AH. Client-side signHash (CLI → CSC signHash → bandwidth-efficient)
#   B.  Server-side signing  (signPdf/form — full pipeline)
#   C.  CSC signDoc/form     (raw CMS signing via form)
# Each with all signature variants:
#   - PAdES B-B / B-T / B-LT / B-LTA (invisible + visible)
#   - PKCS7 (invisible + visible, with/without TSA)
#   - PKCS7 LTV (CRL / OCSP / both / +TSA / +visible)
# Then validates every output:
#   D.  Server validation    (POST /api/v1/validate/form)
#   E.  CLI offline verify   (local verification)
#
# ┌─────────────────────────────────────────────────────────────────┐
# │  ⚠️  DISCLAIMER                                                 │
# │                                                                  │
# │  This test suite runs against a LOCAL prototype server using     │
# │  debug-built binaries (unoptimized) and test certificates        │
# │  (Nowina DSS PKI Factory). All communication is over localhost   │
# │  loopback (127.0.0.1).                                          │
# │                                                                  │
# │  Timing measurements are INDICATIVE ONLY and should NOT be       │
# │  used as production performance benchmarks. Factors affecting    │
# │  timings:                                                        │
# │    • Debug build (no compiler optimizations)                     │
# │    • Loopback network (zero real network latency)                │
# │    • External TSA calls to timestamp.digicert.com add variable   │
# │      network latency (typically 100-500ms per call)              │
# │    • CRL/OCSP fetching from Nowina PKI adds network latency     │
# │    • Machine load and I/O variability                            │
# │                                                                  │
# │  Purpose: Functional correctness validation + relative timing    │
# │  comparison between signing methods (signDoc vs signHash vs      │
# │  server-side signPdf) under identical local conditions.          │
# └─────────────────────────────────────────────────────────────────┘
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

PROJECT="/Users/fdimarh/Documents/Lab/Rustlab/pdf/remote-signature-pdf"
BIN="$PROJECT/target/debug/remote-signature-pdf"
PORT=9100
TSA="http://timestamp.digicert.com"
BASE="http://localhost:$PORT"
SAMPLE="$PROJECT/test-files/sample.pdf"
IMAGE="$PROJECT/test-files/signature-image.png"
OUTDIR="/tmp/signing-retest-$(date +%s)"
REPORT="$OUTDIR/report.txt"

mkdir -p "$OUTDIR"

PASS=0
FAIL=0
TOTAL=0

# ── Timing infrastructure ──────────────────────────────────────
now_ms() { python3 -c "import time; print(int(time.time()*1000))"; }

fmt_ms() {
    local ms=$1
    if [ "$ms" -ge 60000 ]; then
        printf "%dm %d.%03ds" $((ms/60000)) $(((ms%60000)/1000)) $((ms%1000))
    elif [ "$ms" -ge 1000 ]; then
        printf "%d.%03ds" $((ms/1000)) $((ms%1000))
    else
        printf "%dms" "$ms"
    fi
}

# Per-test perf log: "SECTION|TEST_NAME|ELAPSED_MS|SIZE_BYTES|STATUS"
declare -a PERF_LOG=()

# Section timing
declare -A SEC_START_MS=()
declare -A SEC_ELAPSED_MS=()
SEC_ORDER=()

section_start() { SEC_START_MS["$1"]=$(now_ms); SEC_ORDER+=("$1"); }
section_end()   { local e=$(now_ms); SEC_ELAPSED_MS["$1"]=$(( e - ${SEC_START_MS["$1"]} )); }

T_START=0
test_start() { T_START=$(now_ms); }
test_elapsed() { echo $(( $(now_ms) - T_START )); }

ok() {
    PASS=$((PASS+1)); TOTAL=$((TOTAL+1))
    local elapsed=$(test_elapsed)
    echo "  ✅ $1  [$(fmt_ms $elapsed)]"
    PERF_LOG+=("${CUR_SEC}|${CUR_TEST}|${elapsed}|${CUR_SIZE}|PASS")
}
fail() {
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
    local elapsed=$(test_elapsed)
    echo "  ❌ $1  [$(fmt_ms $elapsed)]"
    PERF_LOG+=("${CUR_SEC}|${CUR_TEST}|${elapsed}|0|FAIL")
}

CUR_SEC=""
CUR_TEST=""
CUR_SIZE="0"

SUITE_START_MS=$(now_ms)

{

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  Comprehensive Signing & Validation Test Suite                       ║"
echo "║  $(date '+%Y-%m-%d %H:%M:%S')                                                   ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  ⚠️  LOCAL PROTOTYPE — timings are indicative only                   ║"
echo "║  Debug build · loopback network · Nowina test PKI                    ║"
echo "║  TSA calls to timestamp.digicert.com add network latency             ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ── Setup ──────────────────────────────────────────────────────
pkill -f "remote-signature-pdf server" 2>/dev/null || true
sleep 2

RUST_LOG=warn "$BIN" server --port $PORT &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "FATAL: Server failed to start"; exit 1
fi

TOKEN=$(curl -s -X POST "$BASE/csc/v2/auth/login" \
  -H "Authorization: Basic $(echo -n testuser:testpass | base64)" \
  -H "Content-Type: application/json" \
  -d '{"rememberMe": true}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

echo "Server PID=$SERVER_PID, Port=$PORT"
echo "Output:  $OUTDIR"
echo ""

# ═══════════════════════════════════════════════════════════════
# SECTION A: CLIENT-SIDE SIGNING (CLI sign → CSC signDoc)
# ═══════════════════════════════════════════════════════════════
CUR_SEC="A"
section_start "A"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION A: Client-Side Signing (CLI → CSC signDoc → local embed)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# A1: PAdES variants (invisible)
for LVL in B-B B-T B-LT B-LTA; do
    NAME="A-cli-pades-${LVL}-invisible"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(sign --server-url "$BASE" -u testuser -p testpass \
          --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
          --format pades --level "$LVL")
    if [ "$LVL" != "B-B" ]; then ARGS+=(--tsa-url "$TSA"); fi

    test_start
    if RUST_LOG=warn "$BIN" "${ARGS[@]}" >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
        CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
        ok "$NAME ($CUR_SIZE bytes)"
    else
        fail "$NAME (sign failed)"
    fi
done

# A2: PAdES B-T visible
NAME="A-cli-pades-BT-visible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pades --level B-T --tsa-url "$TSA" \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A3: PKCS7 invisible
NAME="A-cli-pkcs7-invisible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A4: PKCS7 visible
NAME="A-cli-pkcs7-visible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A5: PKCS7 LTV — CRL only (invisible)
NAME="A-cli-pkcs7-crl-only"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A6: PKCS7 LTV — OCSP only (invisible)
NAME="A-cli-pkcs7-ocsp-only"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-ocsp >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A7: PKCS7 LTV — CRL + OCSP (invisible)
NAME="A-cli-pkcs7-crl-ocsp"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A8: PKCS7 LTV — CRL + OCSP + TSA (invisible)
NAME="A-cli-pkcs7-crl-ocsp-tsa"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --tsa-url "$TSA" >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A9: PKCS7 LTV full — CRL + OCSP + TSA + visible
NAME="A-cli-pkcs7-ltv-full-visible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --tsa-url "$TSA" \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

section_end "A"
echo ""
echo "  ⏱  Section A total: $(fmt_ms ${SEC_ELAPSED_MS[A]})"

# ═══════════════════════════════════════════════════════════════
# SECTION AH: CLIENT-SIDE SIGNING VIA CSC signHash
#   (bandwidth-efficient — only 32-byte hash sent over the wire)
#   Supports ALL signing variants: PAdES levels, PKCS7, LTV
# ═══════════════════════════════════════════════════════════════
CUR_SEC="AH"
section_start "AH"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION AH: Client-Side signHash (hash-only, all variants)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# AH1: PAdES all levels — invisible
for LVL in B-B B-T B-LT B-LTA; do
    NAME="AH-cli-signhash-pades-${LVL}-invisible"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(sign --server-url "$BASE" -u testuser -p testpass \
          --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
          --format pades --level "$LVL" --use-sign-hash)
    if [ "$LVL" != "B-B" ]; then ARGS+=(--tsa-url "$TSA"); fi

    test_start
    if RUST_LOG=warn "$BIN" "${ARGS[@]}" >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
        CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
        ok "$NAME ($CUR_SIZE bytes)"
    else
        fail "$NAME (sign failed)"
    fi
done

# AH2: PAdES B-T visible
NAME="AH-cli-signhash-pades-BT-visible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pades --level B-T --tsa-url "$TSA" --use-sign-hash \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH3: PKCS7 invisible
NAME="AH-cli-signhash-pkcs7-invisible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --use-sign-hash >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH4: PKCS7 visible
NAME="AH-cli-signhash-pkcs7-visible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --use-sign-hash \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH5: PKCS7 + TSA (invisible)
NAME="AH-cli-signhash-pkcs7-tsa"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --tsa-url "$TSA" --use-sign-hash >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH6: PKCS7 LTV — CRL only (invisible)
NAME="AH-cli-signhash-pkcs7-crl-only"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --use-sign-hash >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH7: PKCS7 LTV — OCSP only (invisible)
NAME="AH-cli-signhash-pkcs7-ocsp-only"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-ocsp --use-sign-hash >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH8: PKCS7 LTV — CRL + OCSP (invisible)
NAME="AH-cli-signhash-pkcs7-crl-ocsp"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --use-sign-hash >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH9: PKCS7 LTV — CRL + OCSP + TSA (invisible)
NAME="AH-cli-signhash-pkcs7-crl-ocsp-tsa"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --tsa-url "$TSA" --use-sign-hash >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# AH10: PKCS7 LTV full — CRL + OCSP + TSA + visible
NAME="AH-cli-signhash-pkcs7-ltv-full-visible"
CUR_TEST="$NAME"; CUR_SIZE="0"
echo ""
echo "--- $NAME ---"
test_start
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --tsa-url "$TSA" --use-sign-hash \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($CUR_SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

section_end "AH"
echo ""
echo "  ⏱  Section AH total: $(fmt_ms ${SEC_ELAPSED_MS[AH]})"

# ═══════════════════════════════════════════════════════════════
# SECTION B: SERVER-SIDE SIGNING (signPdf/form — full pipeline)
# ═══════════════════════════════════════════════════════════════
CUR_SEC="B"
section_start "B"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION B: Server-Side Signing (POST /api/v1/signPdf/form)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# B1: PAdES all levels — invisible
for LVL in B-B B-T B-LT B-LTA; do
    NAME="B-server-pades-${LVL}-invisible"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.pdf" -w "%{http_code}" \
      -X POST "$BASE/api/v1/signPdf/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@$SAMPLE" \
      -F "signatureFormat=pades" \
      -F "padesLevel=$LVL")
    if [ "$LVL" != "B-B" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi

    test_start
    HTTP=$(curl "${ARGS[@]}")
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$CUR_SIZE"
    if [ "$HTTP" = "200" ] && [ "$CUR_SIZE" -gt 1000 ]; then
        ok "$NAME ($CUR_SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# B2: PAdES all levels — visible
for LVL in B-B B-T B-LT B-LTA; do
    NAME="B-server-pades-${LVL}-visible"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.pdf" -w "%{http_code}" \
      -X POST "$BASE/api/v1/signPdf/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@$SAMPLE" \
      -F "image=@$IMAGE" \
      -F "sigRect=50,600,250,700" \
      -F "sigPage=1" \
      -F "signerName=Test Signer" \
      -F "signatureFormat=pades" \
      -F "padesLevel=$LVL")
    if [ "$LVL" != "B-B" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi

    test_start
    HTTP=$(curl "${ARGS[@]}")
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$CUR_SIZE"
    if [ "$HTTP" = "200" ] && [ "$CUR_SIZE" -gt 1000 ]; then
        ok "$NAME ($CUR_SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# B3: PKCS7 invisible / visible / +TSA
for COMBO in "invisible::" "visible:yes:" "invisible::yes" "visible:yes:yes"; do
    IFS=':' read -r VIS HAS_IMG HAS_TSA <<< "$COMBO"
    LABEL="pkcs7-${VIS}"
    if [ "$HAS_TSA" = "yes" ]; then LABEL="${LABEL}-tsa"; fi
    NAME="B-server-${LABEL}"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.pdf" -w "%{http_code}" \
      -X POST "$BASE/api/v1/signPdf/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@$SAMPLE" \
      -F "signatureFormat=pkcs7")
    if [ "$HAS_IMG" = "yes" ]; then
        ARGS+=(-F "image=@$IMAGE" -F "sigRect=50,600,250,700" -F "signerName=PKCS7 Signer")
    fi
    if [ "$HAS_TSA" = "yes" ]; then
        ARGS+=(-F "timestampUrl=$TSA")
    fi

    test_start
    HTTP=$(curl "${ARGS[@]}")
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$CUR_SIZE"
    if [ "$HTTP" = "200" ] && [ "$CUR_SIZE" -gt 1000 ]; then
        ok "$NAME ($CUR_SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# B4: PKCS7 LTV variants
for COMBO in \
    "pkcs7-crl-only:true:false::" \
    "pkcs7-ocsp-only:false:true::" \
    "pkcs7-crl-ocsp:true:true::" \
    "pkcs7-crl-ocsp-tsa:true:true:yes:" \
    "pkcs7-ltv-full-visible:true:true:yes:yes"; do
    IFS=':' read -r LABEL CRL OCSP HAS_TSA HAS_IMG <<< "$COMBO"
    NAME="B-server-${LABEL}"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.pdf" -w "%{http_code}" \
      -X POST "$BASE/api/v1/signPdf/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@$SAMPLE" \
      -F "signatureFormat=pkcs7" \
      -F "includeCrl=$CRL" \
      -F "includeOcsp=$OCSP")
    if [ "$HAS_TSA" = "yes" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi
    if [ "$HAS_IMG" = "yes" ]; then
        ARGS+=(-F "image=@$IMAGE" -F "sigRect=50,600,250,700" -F "signerName=LTV Signer")
    fi

    test_start
    HTTP=$(curl "${ARGS[@]}")
    CUR_SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$CUR_SIZE"
    if [ "$HTTP" = "200" ] && [ "$CUR_SIZE" -gt 1000 ]; then
        ok "$NAME ($CUR_SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

section_end "B"
echo ""
echo "  ⏱  Section B total: $(fmt_ms ${SEC_ELAPSED_MS[B]})"

# ═══════════════════════════════════════════════════════════════
# SECTION C: CSC signDoc/form (raw CMS signing)
# ═══════════════════════════════════════════════════════════════
CUR_SEC="C"
section_start "C"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION C: CSC signDoc/form (raw CMS)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo -n "ByteRangeContentSample1234567890ABCDEF" > /tmp/signdoc-content.bin

for COMBO in "pades:B-B:" "pades:B-T:yes" "pkcs7::" "pkcs7::yes"; do
    IFS=':' read -r FMT LVL HAS_TSA <<< "$COMBO"
    LABEL="${FMT}"
    if [ -n "$LVL" ]; then LABEL="${LABEL}-${LVL}"; fi
    if [ "$HAS_TSA" = "yes" ]; then LABEL="${LABEL}-tsa"; fi
    NAME="C-signdoc-${LABEL}"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.json" -w "%{http_code}" \
      -X POST "$BASE/csc/v2/signatures/signDoc/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@/tmp/signdoc-content.bin" \
      -F "signatureFormat=$FMT")
    if [ -n "$LVL" ]; then ARGS+=(-F "padesLevel=$LVL"); fi
    if [ "$HAS_TSA" = "yes" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi

    test_start
    HTTP=$(curl "${ARGS[@]}")
    echo "  HTTP=$HTTP"
    if [ "$HTTP" = "200" ]; then
        HAS_SIG=$(python3 -c "import json; print('signature' in json.load(open('$OUTDIR/${NAME}.json')))" 2>/dev/null || echo "false")
        if [ "$HAS_SIG" = "True" ]; then
            ok "$NAME"
        else
            fail "$NAME (missing signature field)"
        fi
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# C2: PKCS7 LTV signDoc variants
for COMBO in "pkcs7-crl-only:true:false:" "pkcs7-ocsp-only:false:true:" "pkcs7-crl-ocsp:true:true:" "pkcs7-crl-ocsp-tsa:true:true:yes"; do
    IFS=':' read -r LABEL CRL OCSP HAS_TSA <<< "$COMBO"
    NAME="C-signdoc-${LABEL}"
    CUR_TEST="$NAME"; CUR_SIZE="0"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.json" -w "%{http_code}" \
      -X POST "$BASE/csc/v2/signatures/signDoc/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@/tmp/signdoc-content.bin" \
      -F "signatureFormat=pkcs7" \
      -F "includeCrl=$CRL" \
      -F "includeOcsp=$OCSP")
    if [ "$HAS_TSA" = "yes" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi

    test_start
    HTTP=$(curl "${ARGS[@]}")
    echo "  HTTP=$HTTP"
    if [ "$HTTP" = "200" ]; then
        HAS_SIG=$(python3 -c "import json; print('signature' in json.load(open('$OUTDIR/${NAME}.json')))" 2>/dev/null || echo "false")
        if [ "$HAS_SIG" = "True" ]; then
            ok "$NAME"
        else
            fail "$NAME (missing signature field)"
        fi
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

rm -f /tmp/signdoc-content.bin

section_end "C"
echo ""
echo "  ⏱  Section C total: $(fmt_ms ${SEC_ELAPSED_MS[C]})"

# ═══════════════════════════════════════════════════════════════
# SECTION D: VALIDATE all signed PDFs via /api/v1/validate/form
# ═══════════════════════════════════════════════════════════════
CUR_SEC="D"
section_start "D"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION D: Server-Side Validation (POST /api/v1/validate/form)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for pdf in "$OUTDIR"/*.pdf; do
    FNAME=$(basename "$pdf")
    CUR_TEST="validate-$FNAME"; CUR_SIZE="0"
    echo ""
    echo "--- validate: $FNAME ---"
    test_start
    HTTP=$(curl -s -o /tmp/val-out.json -w "%{http_code}" \
      -X POST "$BASE/api/v1/validate/form" \
      -F "file=@$pdf")
    if [ "$HTTP" = "200" ]; then
        ALL_VALID=$(python3 -c "import json; print(json.load(open('/tmp/val-out.json'))['allValid'])" 2>/dev/null || echo "?")
        SIG_CNT=$(python3 -c "import json; print(json.load(open('/tmp/val-out.json'))['signatureCount'])" 2>/dev/null || echo "?")
        HAS_TS=$(python3 -c "import json; s=json.load(open('/tmp/val-out.json'))['signatures'][0]; print(s.get('hasTimestamp', False))" 2>/dev/null || echo "?")
        HAS_DSS=$(python3 -c "import json; s=json.load(open('/tmp/val-out.json'))['signatures'][0]; print(s.get('hasDss', False))" 2>/dev/null || echo "?")
        IS_LTV=$(python3 -c "import json; s=json.load(open('/tmp/val-out.json'))['signatures'][0]; print(s.get('isLtvEnabled', False))" 2>/dev/null || echo "?")
        echo "  valid=$ALL_VALID  sigs=$SIG_CNT  ts=$HAS_TS  dss=$HAS_DSS  ltv=$IS_LTV"
        if [ "$ALL_VALID" = "True" ]; then
            ok "validate $FNAME (sigs=$SIG_CNT ts=$HAS_TS dss=$HAS_DSS ltv=$IS_LTV)"
        else
            ERRS=$(python3 -c "import json; s=json.load(open('/tmp/val-out.json'))['signatures'][0]; print(s.get('errors',[])) if not s.get('isValid') else print('?')" 2>/dev/null || echo "?")
            fail "validate $FNAME ($ERRS)"
        fi
    else
        fail "validate $FNAME (HTTP=$HTTP)"
    fi
done

rm -f /tmp/val-out.json

section_end "D"
echo ""
echo "  ⏱  Section D total: $(fmt_ms ${SEC_ELAPSED_MS[D]})"

# ═══════════════════════════════════════════════════════════════
# SECTION E: CLI verify (local offline verification)
# ═══════════════════════════════════════════════════════════════
CUR_SEC="E"
section_start "E"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION E: CLI Verify (local offline)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for pdf in "$OUTDIR"/*.pdf; do
    FNAME=$(basename "$pdf")
    CUR_TEST="verify-$FNAME"; CUR_SIZE="0"
    echo ""
    echo "--- verify: $FNAME ---"
    test_start
    OUTPUT=$(RUST_LOG=error "$BIN" verify --input "$pdf" 2>&1)
    if echo "$OUTPUT" | grep -q "VALID"; then
        TS=$(echo "$OUTPUT" | grep "Has timestamp" | head -1 | awk '{print $NF}')
        DSS=$(echo "$OUTPUT" | grep "Has DSS" | head -1 | awk '{print $NF}')
        LTV=$(echo "$OUTPUT" | grep "LTV enabled" | head -1 | awk '{print $NF}')
        echo "  ts=$TS  dss=$DSS  ltv=$LTV"
        ok "verify $FNAME (ts=$TS dss=$DSS ltv=$LTV)"
    else
        fail "verify $FNAME"
    fi
done

section_end "E"
echo ""
echo "  ⏱  Section E total: $(fmt_ms ${SEC_ELAPSED_MS[E]})"

# ═══════════════════════════════════════════════════════════════
# Cleanup & Summary
# ═══════════════════════════════════════════════════════════════
kill $SERVER_PID 2>/dev/null || true

SUITE_END_MS=$(now_ms)
SUITE_ELAPSED=$((SUITE_END_MS - SUITE_START_MS))

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                          FINAL SUMMARY                              ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  Total:  %-4d                                                       ║\n" $TOTAL
printf "║  Passed: %-4d                                                       ║\n" $PASS
printf "║  Failed: %-4d                                                       ║\n" $FAIL
printf "║  Time:   %-12s                                                ║\n" "$(fmt_ms $SUITE_ELAPSED)"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Section Breakdown                                                   ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
for s in "${SEC_ORDER[@]}"; do
    case "$s" in
        A)   DESC="Client CLI signDoc  (PAdES + PKCS7 + LTV)" ;;
        AH)  DESC="Client CLI signHash (PAdES + PKCS7 + LTV)" ;;
        B)   DESC="Server signPdf/form (PAdES + PKCS7 + LTV)" ;;
        C)   DESC="CSC signDoc/form    (raw CMS variants)   " ;;
        D)   DESC="Server validate/form                      " ;;
        E)   DESC="CLI verify (offline)                      " ;;
        *)   DESC="$s" ;;
    esac
    SEC_CNT=0
    for entry in "${PERF_LOG[@]}"; do
        if [[ "$entry" == "${s}|"* ]]; then SEC_CNT=$((SEC_CNT+1)); fi
    done
    printf "║  %-3s │ %2d tests │ %12s │ %-38s║\n" "$s" "$SEC_CNT" "$(fmt_ms ${SEC_ELAPSED_MS[$s]})" "$DESC"
done
echo "╚══════════════════════════════════════════════════════════════════════╝"

# ══════════════════════════════════════════════════════════════════════
# PERFORMANCE COMPARISON TABLE — signDoc vs signHash vs Server
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "┌───────────────────────────────────────────────────────────────────────────────┐"
echo "│              PERFORMANCE COMPARISON — Signing Methods (A vs AH vs B)          │"
echo "│  ⚠️  Local prototype only — debug build, loopback, Nowina test certificates    │"
echo "│  External TSA/CRL/OCSP calls add variable network latency (100-500ms each)    │"
echo "├───────────────────────────────────────────────────────────────────────────────┤"
printf "│  %-47s│ %9s │ %9s │\n" "Variant" "Time" "Size"
echo "├───────────────────────────────────────────────────────────────────────────────┤"

declare -a COMPARE_KEYS=(
    "pades-B-B-invisible"
    "pades-B-T-invisible"
    "pades-B-LT-invisible"
    "pades-B-LTA-invisible"
    "pades-BT-visible"
    "pkcs7-invisible"
    "pkcs7-visible"
)

# Helper: find entry by name and return "ms|size" or empty
find_entry() {
    local pattern="$1"
    for entry in "${PERF_LOG[@]}"; do
        IFS='|' read -r e_sec e_name e_ms e_size e_stat <<< "$entry"
        if [[ "$e_name" == "$pattern" ]]; then
            if [ "$e_stat" = "PASS" ]; then
                echo "${e_ms}|${e_size}"
            else
                echo "FAIL|0"
            fi
            return
        fi
    done
    echo ""
}

for ck in "${COMPARE_KEYS[@]}"; do
    echo "│                                                                               │"
    printf "│  ▸ %-44s│           │           │\n" "$ck"

    # signDoc (A)
    RES=$(find_entry "A-cli-${ck}")
    if [ -n "$RES" ]; then
        IFS='|' read -r ms sz <<< "$RES"
        if [ "$ms" = "FAIL" ]; then
            printf "│    %-45s│ %9s │ %9s │\n" "Client signDoc  (A)" "FAILED" "-"
        else
            printf "│    %-45s│ %9s │ %7s B │\n" "Client signDoc  (A)" "$(fmt_ms $ms)" "$sz"
        fi
    fi

    # signHash (AH)
    RES=$(find_entry "AH-cli-signhash-${ck}")
    if [ -n "$RES" ]; then
        IFS='|' read -r ms sz <<< "$RES"
        if [ "$ms" = "FAIL" ]; then
            printf "│    %-45s│ %9s │ %9s │\n" "Client signHash (AH)" "FAILED" "-"
        else
            printf "│    %-45s│ %9s │ %7s B │\n" "Client signHash (AH)" "$(fmt_ms $ms)" "$sz"
        fi
    fi

    # Server (B)
    RES=$(find_entry "B-server-${ck}")
    if [ -n "$RES" ]; then
        IFS='|' read -r ms sz <<< "$RES"
        if [ "$ms" = "FAIL" ]; then
            printf "│    %-45s│ %9s │ %9s │\n" "Server signPdf  (B)" "FAILED" "-"
        else
            printf "│    %-45s│ %9s │ %7s B │\n" "Server signPdf  (B)" "$(fmt_ms $ms)" "$sz"
        fi
    fi
done

echo "├───────────────────────────────────────────────────────────────────────────────┤"

# Compute averages
A_TOTAL_MS=0; A_CNT=0
AH_TOTAL_MS=0; AH_CNT=0
B_TOTAL_MS=0; B_CNT=0

for entry in "${PERF_LOG[@]}"; do
    IFS='|' read -r e_sec e_name e_ms e_size e_stat <<< "$entry"
    if [ "$e_stat" != "PASS" ]; then continue; fi
    case "$e_sec" in
        A)  A_TOTAL_MS=$((A_TOTAL_MS + e_ms)); A_CNT=$((A_CNT + 1)) ;;
        AH) AH_TOTAL_MS=$((AH_TOTAL_MS + e_ms)); AH_CNT=$((AH_CNT + 1)) ;;
        B)  B_TOTAL_MS=$((B_TOTAL_MS + e_ms)); B_CNT=$((B_CNT + 1)) ;;
    esac
done

echo "│  Average signing time per test:                                               │"
if [ "$A_CNT" -gt 0 ]; then
    A_AVG=$((A_TOTAL_MS / A_CNT))
    printf "│    Client signDoc  (A):  %9s avg  (%2d tests, %12s total)       │\n" "$(fmt_ms $A_AVG)" "$A_CNT" "$(fmt_ms $A_TOTAL_MS)"
fi
if [ "$AH_CNT" -gt 0 ]; then
    AH_AVG=$((AH_TOTAL_MS / AH_CNT))
    printf "│    Client signHash (AH): %9s avg  (%2d tests, %12s total)       │\n" "$(fmt_ms $AH_AVG)" "$AH_CNT" "$(fmt_ms $AH_TOTAL_MS)"
fi
if [ "$B_CNT" -gt 0 ]; then
    B_AVG=$((B_TOTAL_MS / B_CNT))
    printf "│    Server signPdf  (B):  %9s avg  (%2d tests, %12s total)       │\n" "$(fmt_ms $B_AVG)" "$B_CNT" "$(fmt_ms $B_TOTAL_MS)"
fi

echo "├───────────────────────────────────────────────────────────────────────────────┤"
echo "│  Notes:                                                                       │"
echo "│  • signHash sends only 32 bytes vs full byte-range content (signDoc)          │"
echo "│  • Server signPdf handles full pipeline in one HTTP call (fewest round-trips) │"
echo "│  • B-LT/B-LTA include DSS dictionary + document timestamp (extra I/O)        │"
echo "│  • Tests with TSA/CRL/OCSP include external network calls                    │"
echo "├───────────────────────────────────────────────────────────────────────────────┤"
echo "│  ⚠️  DISCLAIMER: Debug build, loopback, Nowina test PKI.                      │"
echo "│  These timings are for relative comparison only, NOT production benchmarks.   │"
echo "└───────────────────────────────────────────────────────────────────────────────┘"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "🎉 ALL $TOTAL TESTS PASSED in $(fmt_ms $SUITE_ELAPSED)"
else
    echo "⚠️  $FAIL/$TOTAL TEST(S) FAILED in $(fmt_ms $SUITE_ELAPSED)"
fi
echo ""
echo "Output: $OUTDIR"
echo "Report: $REPORT"

} 2>&1 | tee "$REPORT"

