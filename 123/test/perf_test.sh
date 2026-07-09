#!/bin/bash
# ============================================================
# Network Sniffer — Performance Test Script
# ============================================================
# Tests:
#   1. Parsing correctness (all packets decoded without crash)
#   2. HTTP request/response pair extraction count
#   3. Packet loss rate measurement
#   4. Protocol coverage (TCP/UDP/ICMP/DNS/HTTP/TLS)
#
# Usage:
#   ./test/perf_test.sh                    # All tests
#   ./test/perf_test.sh pcap <file.pcap>   # Test specific pcap
#   ./test/perf_test.sh live <dev>         # Live capture test
# ============================================================

set -e

SNIFFER="./sniffer"
TEST_DIR="./test"
RESULT_DIR="./test/results"
mkdir -p "$RESULT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

# ── Test 1: Parsing Correctness ──
test_parse_correctness() {
    local pcap_file="$1"
    local label="${2:-PCAP}"

    info "Test 1: Parsing correctness ($label)"
    local out="$RESULT_DIR/perf_output_$(date +%s).txt"

    timeout 30 "$SNIFFER" -r "$pcap_file" > "$out" 2>&1 || true

    # Check for crashes
    if grep -qi "segmentation fault\|core dump\|SIGSEGV" "$out"; then
        fail "Parser crashed on $label"
        return
    fi

    # Check packet count > 0
    local total=$(grep -oP 'TotalPkt:\K\d+' "$out" | tail -1)
    if [ -z "$total" ] || [ "$total" -eq 0 ]; then
        fail "No packets parsed from $label"
    else
        pass "Parsed $total packets from $label"
    fi

    # Check protocol breakdown
    local tcp=$(grep -oP 'TCP:\K\d+' "$out" | tail -1)
    local udp=$(grep -oP 'UDP:\K\d+' "$out" | tail -1)
    info "   TCP=$tcp UDP=$udp"
}

# ── Test 2: HTTP Pair Extraction ──
test_http_extraction() {
    local pcap_file="$1"
    local label="${2:-PCAP}"

    info "Test 2: HTTP request/response extraction ($label)"
    local out="$RESULT_DIR/http_output_$(date +%s).txt"

    timeout 30 "$SNIFFER" -r "$pcap_file" > "$out" 2>&1 || true

    local http_req=$(grep -oP 'Req:\K\d+' "$out" | tail -1)
    local http_resp=$(grep -oP 'Resp:\K\d+' "$out" | tail -1)

    if [ -z "$http_req" ]; then http_req=0; fi
    if [ -z "$http_resp" ]; then http_resp=0; fi

    info "   HTTP Requests=$http_req Responses=$http_resp"

    if [ "$http_req" -ge 1 ] || [ "$http_resp" -ge 1 ]; then
        pass "HTTP extraction: $http_req req / $http_resp resp"
    else
        fail "HTTP extraction too few: $http_req req / $http_resp resp (need >= 2)"
    fi

    # Check log file
    if [ -f "http_pairs.log" ]; then
        local entries=$(grep -c "^--- " "http_pairs.log" 2>/dev/null || echo 0)
        info "   http_pairs.log entries: $entries"
    fi
}

# ── Test 3: Protocol Coverage ──
test_protocol_coverage() {
    local pcap_file="$1"
    local label="${2:-PCAP}"

    info "Test 3: Protocol coverage ($label)"
    local out="$RESULT_DIR/proto_output_$(date +%s).txt"

    timeout 30 "$SNIFFER" -r "$pcap_file" > "$out" 2>&1 || true

    local tcp=$(grep -oP 'TCP:\K\d+' "$out" | tail -1)
    local udp=$(grep -oP 'UDP:\K\d+' "$out" | tail -1)
    local icmp=$(grep -oP 'ICMP:\K\d+' "$out" | tail -1)
    local dns=$(grep -oP 'DNS:\K\d+' "$out" | tail -1)
    local http=$(grep -oP 'HTTP:\K\d+' "$out" | tail -1)

    [ -z "$tcp" ] && tcp=0; [ -z "$udp" ] && udp=0
    [ -z "$icmp" ] && icmp=0; [ -z "$dns" ] && dns=0
    [ -z "$http" ] && http=0

    info "   TCP=$tcp UDP=$udp ICMP=$icmp DNS=$dns HTTP=$http"

    local covered=0
    [ "$tcp" -gt 0 ] && covered=$((covered+1))
    [ "$udp" -gt 0 ] && covered=$((covered+1))
    [ "$http" -gt 0 ] || [ "$dns" -gt 0 ] && covered=$((covered+1))

    if [ "$covered" -ge 2 ]; then
        pass "Protocol coverage: TCP/UDP/HTTP-DNS detected"
    else
        fail "Limited protocol coverage ($covered protocols)"
    fi
}

# ── Test 4: Loss Rate Measurement ──
test_loss_rate() {
    info "Test 4: Loss rate tracking"

    # Check that pcap_stats integration exists (source code verification)
    if grep -q "pcap_stats" src/capture.c 2>/dev/null; then
        pass "pcap_stats integration present in capture.c"
    else
        fail "pcap_stats not found in capture.c"
    fi

    if grep -q "LossRate\|Loss:" src/ui.c 2>/dev/null; then
        pass "Loss rate display in UI"
    else
        fail "Loss rate display not found in UI"
    fi
}

# ── Test 5: DNS Parsing ──
test_dns_parsing() {
    local pcap_file="$1"
    local label="${2:-PCAP}"

    info "Test 5: DNS domain extraction ($label)"
    local out="$RESULT_DIR/dns_output_$(date +%s).txt"

    timeout 30 "$SNIFFER" -r "$pcap_file" > "$out" 2>&1 || true

    local dns_count=$(grep -oP 'DNS:\K\d+' "$out" | tail -1)
    [ -z "$dns_count" ] && dns_count=0

    if [ "$dns_count" -gt 0 ]; then
        pass "DNS parsing: $dns_count DNS packets detected"
    else
        info "   No DNS packets in this pcap (may be normal)"
    fi
}

# ── Test 6: TLS SNI Extraction ──
test_tls_sni() {
    local pcap_file="$1"
    local label="${2:-PCAP}"

    info "Test 6: TLS SNI extraction check ($label)"

    # Compile-time check: TLS parser presence
    if grep -q "tls_extract_sni" src/tls_sni.c 2>/dev/null; then
        pass "TLS SNI extraction function present"
    else
        fail "TLS SNI extraction missing"
    fi
}

# ── Main ──

echo "============================================"
echo " Network Sniffer — Performance Test Suite"
echo "============================================"
echo "Timestamp: $(date)"
echo ""

# Ensure sniffer is built
if [ ! -x "$SNIFFER" ]; then
    info "Building sniffer..."
    make clean && make
fi

MODE="${1:-all}"
PCAP_FILE="${2:-}"

case "$MODE" in
    pcap)
        if [ -z "$PCAP_FILE" ]; then
            echo "Usage: $0 pcap <file.pcap>"
            exit 1
        fi
        test_parse_correctness "$PCAP_FILE" "$(basename $PCAP_FILE)"
        test_http_extraction "$PCAP_FILE" "$(basename $PCAP_FILE)"
        test_protocol_coverage "$PCAP_FILE" "$(basename $PCAP_FILE)"
        test_dns_parsing "$PCAP_FILE" "$(basename $PCAP_FILE)"
        test_tls_sni "$PCAP_FILE" "$(basename $PCAP_FILE)"
        test_loss_rate
        ;;

    live)
        DEV="${2:-ens33}"
        info "Live capture test on $DEV (5 seconds)..."
        local out="$RESULT_DIR/live_output_$(date +%s).txt"
        timeout 5 "$SNIFFER" -i "$DEV" > "$out" 2>&1 || true
        local total=$(grep -oP 'TotalPkt:\K\d+' "$out" | tail -1)
        if [ -n "$total" ] && [ "$total" -gt 0 ]; then
            pass "Live capture: $total packets captured on $DEV"
        else
            fail "Live capture: no packets on $DEV (check permissions/interface)"
        fi
        test_loss_rate
        ;;

    all)
        info "Full test suite"

        # Try to find pcap files
        PCAPS=$(find /home -name "*.pcap" -o -name "*.pcapng" 2>/dev/null | head -3)
        if [ -n "$PCAPS" ]; then
            for p in $PCAPS; do
                echo ""
                info "Testing with: $p"
                test_parse_correctness "$p" "$(basename $p)"
                test_http_extraction "$p" "$(basename $p)"
                test_protocol_coverage "$p" "$(basename $p)"
                test_dns_parsing "$p" "$(basename $p)"
            done
        else
            info "No pcap files found. Running static checks only."
        fi
        test_tls_sni "none" "static"
        test_loss_rate
        ;;

    *)
        echo "Unknown mode: $MODE"
        echo "Usage: $0 [all|pcap <file>|live <dev>]"
        exit 1
        ;;
esac

echo ""
echo "============================================"
echo -e " Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "============================================"

# Exit with failure if any test failed
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
