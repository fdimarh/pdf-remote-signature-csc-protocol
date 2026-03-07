#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# Comprehensive Signing & Validation Test
# ═══════════════════════════════════════════════════════════════════════
# Tests ALL signing methods:
#   A. Client-side signing (CLI → CSC signDoc → embed locally)
#   B. Server-side signing (signPdf/form — full pipeline)
#   C. CSC signDoc/form (raw CMS signing via form)
# Each with all signature variants:
#   - PAdES B-B / B-T / B-LT / B-LTA (invisible + visible)
#   - PKCS7 (invisible + visible, with/without TSA)
# Then validates every output via server /api/v1/validate/form
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
DETAILS=""

ok()   { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); DETAILS+="  ✅ $1\n"; echo "  ✅ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); DETAILS+="  ❌ $1\n"; echo "  ❌ $1"; }

log() { echo "$1" | tee -a "$REPORT"; }

{

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Comprehensive Signing & Validation Retest                    ║"
echo "║  $(date '+%Y-%m-%d %H:%M:%S')                                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
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
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION A: Client-Side Signing (CLI → CSC signDoc → local embed)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# A1: PAdES variants (invisible)
for LVL in B-B B-T B-LT B-LTA; do
    NAME="A-cli-pades-${LVL}-invisible"
    echo ""
    echo "--- $NAME ---"
    ARGS=(sign --server-url "$BASE" -u testuser -p testpass \
          --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
          --format pades --level "$LVL")
    if [ "$LVL" != "B-B" ]; then ARGS+=(--tsa-url "$TSA"); fi

    if RUST_LOG=warn "$BIN" "${ARGS[@]}" >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
        SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
        ok "$NAME ($SIZE bytes)"
    else
        fail "$NAME (sign failed)"
    fi
done

# A2: PAdES B-T visible
NAME="A-cli-pades-BT-visible"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pades --level B-T --tsa-url "$TSA" \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A3: PKCS7 invisible
NAME="A-cli-pkcs7-invisible"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A4: PKCS7 visible
NAME="A-cli-pkcs7-visible"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A5: PKCS7 LTV — CRL only (invisible)
NAME="A-cli-pkcs7-crl-only"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A6: PKCS7 LTV — OCSP only (invisible)
NAME="A-cli-pkcs7-ocsp-only"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-ocsp >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A7: PKCS7 LTV — CRL + OCSP (invisible)
NAME="A-cli-pkcs7-crl-ocsp"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A8: PKCS7 LTV — CRL + OCSP + TSA (invisible)
NAME="A-cli-pkcs7-crl-ocsp-tsa"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --tsa-url "$TSA" >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# A9: PKCS7 LTV full — CRL + OCSP + TSA + visible
NAME="A-cli-pkcs7-ltv-full-visible"
echo ""
echo "--- $NAME ---"
if RUST_LOG=warn "$BIN" sign --server-url "$BASE" -u testuser -p testpass \
    --input "$SAMPLE" --output "$OUTDIR/${NAME}.pdf" \
    --format pkcs7 --include-crl --include-ocsp --tsa-url "$TSA" \
    --image "$IMAGE" --sig-rect "50,600,250,700" --sig-page 1 >/dev/null 2>&1 && [ -f "$OUTDIR/${NAME}.pdf" ]; then
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" | tr -d ' ')
    ok "$NAME ($SIZE bytes)"
else
    fail "$NAME (sign failed)"
fi

# ═══════════════════════════════════════════════════════════════
# SECTION B: SERVER-SIDE SIGNING (signPdf/form — full pipeline)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION B: Server-Side Signing (POST /api/v1/signPdf/form)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# B1: PAdES all levels — invisible
for LVL in B-B B-T B-LT B-LTA; do
    NAME="B-server-pades-${LVL}-invisible"
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.pdf" -w "%{http_code}" \
      -X POST "$BASE/api/v1/signPdf/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@$SAMPLE" \
      -F "signatureFormat=pades" \
      -F "padesLevel=$LVL")
    if [ "$LVL" != "B-B" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi

    HTTP=$(curl "${ARGS[@]}")
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$SIZE"
    if [ "$HTTP" = "200" ] && [ "$SIZE" -gt 1000 ]; then
        ok "$NAME ($SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# B2: PAdES all levels — visible
for LVL in B-B B-T B-LT B-LTA; do
    NAME="B-server-pades-${LVL}-visible"
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

    HTTP=$(curl "${ARGS[@]}")
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$SIZE"
    if [ "$HTTP" = "200" ] && [ "$SIZE" -gt 1000 ]; then
        ok "$NAME ($SIZE bytes)"
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

    HTTP=$(curl "${ARGS[@]}")
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$SIZE"
    if [ "$HTTP" = "200" ] && [ "$SIZE" -gt 1000 ]; then
        ok "$NAME ($SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# B4: PKCS7 LTV variants (CRL/OCSP/both, ±TSA, ±visible)
# Format: "label:crl:ocsp:tsa:img"
for COMBO in \
    "pkcs7-crl-only:true:false::" \
    "pkcs7-ocsp-only:false:true::" \
    "pkcs7-crl-ocsp:true:true::" \
    "pkcs7-crl-ocsp-tsa:true:true:yes:" \
    "pkcs7-ltv-full-visible:true:true:yes:yes"; do
    IFS=':' read -r LABEL CRL OCSP HAS_TSA HAS_IMG <<< "$COMBO"
    NAME="B-server-${LABEL}"
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

    HTTP=$(curl "${ARGS[@]}")
    SIZE=$(wc -c < "$OUTDIR/${NAME}.pdf" 2>/dev/null | tr -d ' ')
    echo "  HTTP=$HTTP, Size=$SIZE"
    if [ "$HTTP" = "200" ] && [ "$SIZE" -gt 1000 ]; then
        ok "$NAME ($SIZE bytes)"
    else
        fail "$NAME (HTTP=$HTTP)"
    fi
done

# ═══════════════════════════════════════════════════════════════
# SECTION C: CSC signDoc/form (raw CMS signing)
# ═══════════════════════════════════════════════════════════════
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
    echo ""
    echo "--- $NAME ---"
    ARGS=(-s -o "$OUTDIR/${NAME}.json" -w "%{http_code}" \
      -X POST "$BASE/csc/v2/signatures/signDoc/form" \
      -H "Authorization: Bearer $TOKEN" \
      -F "file=@/tmp/signdoc-content.bin" \
      -F "signatureFormat=$FMT")
    if [ -n "$LVL" ]; then ARGS+=(-F "padesLevel=$LVL"); fi
    if [ "$HAS_TSA" = "yes" ]; then ARGS+=(-F "timestampUrl=$TSA"); fi

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

# C2: PKCS7 LTV signDoc variants (CRL/OCSP/both, ±TSA)
for COMBO in "pkcs7-crl-only:true:false:" "pkcs7-ocsp-only:false:true:" "pkcs7-crl-ocsp:true:true:" "pkcs7-crl-ocsp-tsa:true:true:yes"; do
    IFS=':' read -r LABEL CRL OCSP HAS_TSA <<< "$COMBO"
    NAME="C-signdoc-${LABEL}"
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

# ═══════════════════════════════════════════════════════════════
# SECTION D: VALIDATE all signed PDFs via /api/v1/validate/form
# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION D: Server-Side Validation (POST /api/v1/validate/form)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for pdf in "$OUTDIR"/*.pdf; do
    FNAME=$(basename "$pdf")
    echo ""
    echo "--- validate: $FNAME ---"
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
            # Show errors
            ERRS=$(python3 -c "import json; s=json.load(open('/tmp/val-out.json'))['signatures'][0]; print(s.get('errors',[])) if not s.get('isValid') else print('?')" 2>/dev/null || echo "?")
            fail "validate $FNAME ($ERRS)"
        fi
    else
        fail "validate $FNAME (HTTP=$HTTP)"
    fi
done

rm -f /tmp/val-out.json

# ═══════════════════════════════════════════════════════════════
# SECTION E: CLI verify (local offline verification)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECTION E: CLI Verify (local offline)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for pdf in "$OUTDIR"/*.pdf; do
    FNAME=$(basename "$pdf")
    echo ""
    echo "--- verify: $FNAME ---"
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

# ═══════════════════════════════════════════════════════════════
# Cleanup & Summary
# ═══════════════════════════════════════════════════════════════
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                     FINAL SUMMARY                             ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
printf "║  Total:  %-4d                                                ║\n" $TOTAL
printf "║  Passed: %-4d                                                ║\n" $PASS
printf "║  Failed: %-4d                                                ║\n" $FAIL
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  A: Client CLI sign (PAdES B-B/T/LT/LTA + PKCS7 inv/vis)    ║"
echo "║  B: Server signPdf/form (PAdES 4×inv + 4×vis + PKCS7 ×4)    ║"
echo "║  C: CSC signDoc/form (PAdES B-B/B-T + PKCS7 ×2)             ║"
echo "║  D: Server validate/form (all signed PDFs)                    ║"
echo "║  E: CLI verify (all signed PDFs)                              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "🎉 ALL $TOTAL TESTS PASSED"
else
    echo "⚠️  $FAIL/$TOTAL TEST(S) FAILED"
fi
echo ""
echo "Output: $OUTDIR"
echo "Report: $REPORT"

} 2>&1 | tee "$REPORT"

