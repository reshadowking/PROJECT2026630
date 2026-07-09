#!/bin/bash
# ============================================================
# UI Keyboard Binding — Acceptance Test Suite
# ============================================================
# 验收标准:
#   AC1: 左/右键(KEY_LEFT/KEY_RIGHT) 切换视图（←上一个，→下一个）
#   AC2: 上/下键(KEY_UP/KEY_DOWN) 控制左侧抓取列表选择
#   AC3: PgUp/PgDn(KEY_NPAGE/KEY_PPAGE) 控制左侧列表翻页（非右侧detail_scroll）
#   AC4: Tab 键已移除（不再导致重复按下卡死）
#
# 测试方法:
#   Part A: 静态源码验证（grep）
#   Part B: pexpect 运行时交互测试
# ============================================================

set -e

SNIFFER="./sniffer"
SRC_DIR="./src"
INC_DIR="./include"
TEST_PCAP="/tmp/test_ui.pcap"
RESULT_DIR="./test/results"
mkdir -p "$RESULT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }
section() { echo ""; echo -e "${CYAN}━━━ $1 ━━━${NC}"; }

# ══════════════════════════════════════════════════════════════
# PART A: 静态源码验证
# ══════════════════════════════════════════════════════════════

section "Part A: Static Source Code Verification"

# ── AC1: KEY_LEFT / KEY_RIGHT 切换视图 ──
test_ac1_static() {
    info "AC1: KEY_LEFT/KEY_RIGHT should switch views (Tab removed)"

    local func_body
    func_body=$(awk '/^int ui_handle_input\(void\)/{found=1; depth=0}
                      found{
                          for(i=1;i<=length($0);i++){
                              c=substr($0,i,1);
                              if(c=="{") depth++;
                              if(c=="}") depth--;
                          }
                          print;
                          if(depth==0 && /}/) exit;
                      }' "$SRC_DIR/ui.c")

    local code_only
    code_only=$(echo "$func_body" | grep -v '^\s*/\*\|\*/' | grep -v '^\s*//' | grep -v '/\*.*\*/')

    # KEY_LEFT should exist and switch to previous view
    if echo "$code_only" | grep -q 'KEY_LEFT'; then
        pass "AC1: KEY_LEFT handler present"
    else
        fail "AC1: KEY_LEFT handler missing"
    fi

    # KEY_RIGHT should exist and switch to next view
    if echo "$code_only" | grep -q 'KEY_RIGHT'; then
        pass "AC1: KEY_RIGHT handler present"
    else
        fail "AC1: KEY_RIGHT handler missing"
    fi

    # KEY_LEFT should modify g_current_view (view switching)
    if echo "$code_only" | grep -A 5 'KEY_LEFT' | grep -q 'g_current_view'; then
        pass "AC1: KEY_LEFT modifies g_current_view (switches view)"
    else
        fail "AC1: KEY_LEFT does not switch views"
    fi

    if echo "$code_only" | grep -A 5 'KEY_RIGHT' | grep -q 'g_current_view'; then
        pass "AC1: KEY_RIGHT modifies g_current_view (switches view)"
    else
        fail "AC1: KEY_RIGHT does not switch views"
    fi
}

# ── AC2: KEY_UP / KEY_DOWN 保留，控制左侧列表选择 ──
test_ac2_static() {
    info "AC2: KEY_UP/KEY_DOWN should control left-list packet selection"

    local func_body
    func_body=$(awk '/^int ui_handle_input\(void\)/{found=1; depth=0}
                      found{
                          for(i=1;i<=length($0);i++){
                              c=substr($0,i,1);
                              if(c=="{") depth++;
                              if(c=="}") depth--;
                          }
                          print;
                          if(depth==0 && /}/) exit;
                      }' "$SRC_DIR/ui.c")

    # KEY_UP should exist and modify pkt_selected
    if echo "$func_body" | grep -q 'KEY_UP'; then
        pass "AC2: KEY_UP handler present"
    else
        fail "AC2: KEY_UP handler missing"
    fi

    if echo "$func_body" | grep -q 'KEY_DOWN'; then
        pass "AC2: KEY_DOWN handler present"
    else
        fail "AC2: KEY_DOWN handler missing"
    fi

    # Verify KEY_UP block modifies pkt_selected (not just present but functional)
    if echo "$func_body" | grep -A 10 'KEY_UP' | grep -q 'pkt_selected'; then
        pass "AC2: KEY_UP modifies pkt_selected (selects packets)"
    else
        fail "AC2: KEY_UP does not modify pkt_selected"
    fi

    if echo "$func_body" | grep -A 10 'KEY_DOWN' | grep -q 'pkt_selected'; then
        pass "AC2: KEY_DOWN modifies pkt_selected (selects packets)"
    else
        fail "AC2: KEY_DOWN does not modify pkt_selected"
    fi
}

# ── AC3: KEY_NPAGE/KEY_PPAGE 控制左侧列表翻页（非 detail_scroll） ──
test_ac3_static() {
    info "AC3: PgUp/PgDn should page left-list, NOT detail_scroll"

    local func_body
    func_body=$(awk '/^int ui_handle_input\(void\)/{found=1; depth=0}
                      found{
                          for(i=1;i<=length($0);i++){
                              c=substr($0,i,1);
                              if(c=="{") depth++;
                              if(c=="}") depth--;
                          }
                          print;
                          if(depth==0 && /}/) exit;
                      }' "$SRC_DIR/ui.c")

    # KEY_NPAGE should be present
    if echo "$func_body" | grep -q 'KEY_NPAGE'; then
        pass "AC3: KEY_NPAGE handler present"
    else
        fail "AC3: KEY_NPAGE handler missing"
    fi

    if echo "$func_body" | grep -q 'KEY_PPAGE'; then
        pass "AC3: KEY_PPAGE handler present"
    else
        fail "AC3: KEY_PPAGE handler missing"
    fi

    # KEY_NPAGE/KEY_PPAGE should NOT reference detail_scroll
    if echo "$func_body" | grep -A 20 'KEY_NPAGE\|KEY_PPAGE' | grep -q 'detail_scroll'; then
        fail "AC3: PgUp/PgDn still references detail_scroll (should control left list)"
    else
        pass "AC3: PgUp/PgDn does NOT reference detail_scroll"
    fi

    # Should reference pkt_selected or list_scroll (left panel control)
    if echo "$func_body" | grep -A 20 'KEY_NPAGE\|KEY_PPAGE' | grep -q 'pkt_selected'; then
        pass "AC3: PgUp/PgDn modifies pkt_selected (left-list paging)"
    elif echo "$func_body" | grep -A 20 'KEY_NPAGE\|KEY_PPAGE' | grep -q 'list_scroll'; then
        pass "AC3: PgUp/PgDn modifies list_scroll (left-list paging)"
    else
        fail "AC3: PgUp/PgDn does NOT control left panel (pkt_selected/list_scroll)"
    fi

    # Should use calc_layout for page size calculation
    if echo "$func_body" | grep -A 20 'KEY_NPAGE\|KEY_PPAGE' | grep -q 'calc_layout\|body_h'; then
        pass "AC3: PgUp/PgDn uses calc_layout for proper page size"
    else
        info "AC3: PgUp/PgDn may not use dynamic page size (uses fixed value)"
    fi
}

# ── AC4: Tab 键已移除，不再导致卡死 ──
test_ac4_static() {
    info "AC4: Tab (\\\\t) should be removed from ui_handle_input()"

    local func_body
    func_body=$(awk '/^int ui_handle_input\(void\)/{found=1; depth=0}
                      found{
                          for(i=1;i<=length($0);i++){
                              c=substr($0,i,1);
                              if(c=="{") depth++;
                              if(c=="}") depth--;
                          }
                          print;
                          if(depth==0 && /}/) exit;
                      }' "$SRC_DIR/ui.c")

    local code_only
    code_only=$(echo "$func_body" | grep -v '^\s*/\*\|\*/' | grep -v '^\s*//' | grep -v '/\*.*\*/')

    # Tab as '\t' escape should NOT be in the function body (code only)
    if echo "$code_only" | grep -q $'\\\\t'; then
        fail "AC4: Tab (\\\\t) still present in ui_handle_input() — should be removed"
    else
        pass "AC4: Tab (\\\\t) removed from ui_handle_input()"
    fi

    # KEY_BTAB should NOT be present
    if echo "$code_only" | grep -q 'KEY_BTAB'; then
        fail "AC4: KEY_BTAB still present in ui_handle_input() — should be removed"
    else
        pass "AC4: KEY_BTAB removed from ui_handle_input()"
    fi

    # Verify there's a comment explaining Tab removal
    if echo "$func_body" | grep -q 'Tab.*removed\|removed.*Tab\|Tab.*freeze'; then
        pass "AC4: Tab removal explanation comment present"
    else
        info "AC4: No Tab removal comment found (optional)"
    fi
}

# ── Status bar hotkey hint updated ──
test_hotkey_hint() {
    info "Extra: Status bar hotkey hint reflects new bindings"

    if grep -q '<-/->=View' "$SRC_DIR/ui.c"; then
        pass "Status bar: '<-/->=View' hint correct"
    elif grep -q 'PgUp/PgDn=Page' "$SRC_DIR/ui.c"; then
        pass "Status bar: PgUp/PgDn=Page hint present"
    else
        fail "Status bar: hotkey hint not updated"
    fi
}

# ══════════════════════════════════════════════════════════════
# PART B: pexpect 运行时交互测试
# ══════════════════════════════════════════════════════════════

section "Part B: Runtime Interactive Test (pexpect)"

run_pexpect_test() {
    info "Launching sniffer in UI mode with test pcap..."

    python3 << 'PYEOF'
import pexpect
import sys
import os
import time

SNIFFER = "./sniffer"
PCAP = "/tmp/test_ui.pcap"
TIMEOUT = 15

passed = 0
failed = 0

def tpass(msg):
    global passed
    print(f"  \033[0;32m[PASS]\033[0m {msg}")
    passed += 1

def tfail(msg):
    global failed
    print(f"  \033[0;31m[FAIL]\033[0m {msg}")
    failed += 1

def tinfo(msg):
    print(f"  \033[1;33m[INFO]\033[0m {msg}")

# ── Spawn ──
try:
    child = pexpect.spawn(f'{SNIFFER} -u -r {PCAP}', encoding='utf-8',
                          dimensions=(30, 100), timeout=TIMEOUT)
except Exception as e:
    print(f"  [FAIL] Cannot spawn sniffer: {e}")
    sys.exit(1)

time.sleep(1.5)  # Wait for UI to render and packets to load

# Check the process is alive
if not child.isalive():
    tfail("Sniffer process died on startup")
    print(f"  Before: {child.before}")
    sys.exit(1)
tpass("Sniffer started successfully with ncurses UI")

# ── Check status bar contains expected text ──
try:
    child.send(chr(27) + '[6n')  # ANSI: request cursor position (may be ignored)
    time.sleep(0.3)
    # Just read whatever is available
    output = child.read_nonblocking(size=65535, timeout=1)
except pexpect.TIMEOUT:
    output = child.before or ""
except Exception:
    output = ""

# Verify the program didn't crash during initial rendering
if child.isalive():
    tpass("UI rendered without crash (process alive)")
else:
    tfail("UI crashed during initial rendering")
    sys.exit(1)

# ── Test 1: Press Up/Down keys — should not crash ──
tinfo("Test B1: Sending KEY_UP x5, KEY_DOWN x5...")
try:
    for _ in range(5):
        child.send('\033[A')  # KEY_UP
        time.sleep(0.05)
    for _ in range(5):
        child.send('\033[B')  # KEY_DOWN
        time.sleep(0.05)
    time.sleep(0.3)
    if child.isalive():
        tpass("B1: Up/Down keys handled without crash")
    else:
        tfail("B1: Program crashed after Up/Down keys")
except Exception as e:
    tfail(f"B1: Exception during Up/Down test: {e}")

# ── Test 2: Press PgUp/PgDn — should page through left list ──
tinfo("Test B2: Sending KEY_PPAGE x3, KEY_NPAGE x3...")
try:
    for _ in range(3):
        child.send('\033[5~')  # KEY_PPAGE (Page Up)
        time.sleep(0.05)
    for _ in range(3):
        child.send('\033[6~')  # KEY_NPAGE (Page Down)
        time.sleep(0.05)
    time.sleep(0.3)
    if child.isalive():
        tpass("B2: PgUp/PgDn keys handled without crash")
    else:
        tfail("B2: Program crashed after PgUp/PgDn keys")
except Exception as e:
    tfail(f"B2: Exception during PgUp/PgDn test: {e}")

# ── Test 3: Press Left/Right keys — should switch views (AC1) ──
tinfo("Test B3: Sending KEY_LEFT x3, KEY_RIGHT x3 (should switch views)...")
try:
    for _ in range(3):
        child.send('\033[D')  # KEY_LEFT → previous view
        time.sleep(0.05)
    for _ in range(3):
        child.send('\033[C')  # KEY_RIGHT → next view
        time.sleep(0.05)
    time.sleep(0.3)
    if child.isalive():
        tpass("B3: Left/Right view switching works (no crash)")
    else:
        tfail("B3: Program crashed after Left/Right keys")
except Exception as e:
    tfail(f"B3: Exception during Left/Right test: {e}")

# ── Test 4: Tab should be ignored (removed, no effect) ──
tinfo("Test B4: Sending Tab x5 (should be ignored, no freeze)...")
try:
    for _ in range(5):
        child.send('\t')  # Tab — should be ignored
        time.sleep(0.08)
    time.sleep(0.3)
    if child.isalive():
        tpass("B4: Tab key ignored (no crash, no freeze)")
    else:
        tfail("B4: Program crashed/froze after Tab keys")
except Exception as e:
    tfail(f"B4: Exception during Tab test: {e}")

# ── Test 5: Rapid key sequence stress test ──
tinfo("Test B5: Rapid mixed key sequence...")
try:
    keys = [
        '\033[A', '\033[A', '\033[B',  # Up Up Down
        '\033[6~', '\033[5~',          # PgDn PgUp
        '\033[D', '\033[C',            # Left Right
        '\033[A', '\033[6~', '\033[B', # Up PgDn Down
    ]
    for k in keys:
        child.send(k)
        time.sleep(0.03)
    time.sleep(0.5)
    if child.isalive():
        tpass("B5: Rapid mixed key sequence handled without crash")
    else:
        tfail("B5: Program crashed during rapid key sequence")
except Exception as e:
    tfail(f"B5: Exception during rapid sequence: {e}")

# ── Test 6: Filter keys (1-6) still work ──
tinfo("Test B6: Filter hotkeys (1-6)...")
try:
    for ch in ['1', '2', '3', '4', '5', '6', '1']:
        child.send(ch)
        time.sleep(0.05)
    time.sleep(0.3)
    if child.isalive():
        tpass("B6: Filter keys (1-6) work without crash")
    else:
        tfail("B6: Program crashed on filter keys")
except Exception as e:
    tfail(f"B6: Exception during filter test: {e}")

# ── Quit ──
tinfo("Sending 'q' to quit...")
try:
    child.send('q')
    time.sleep(0.5)
    child.expect(pexpect.EOF, timeout=3)
    tpass("Program exited normally after 'q'")
except Exception as e:
    tinfo(f"Program exit: {e} (may be normal)")
    if not child.isalive():
        tpass("Program terminated (normal)")

child.close()

# ── Summary ──
print()
print(f"  ─── Runtime Results: {passed} passed, {failed} failed ───")
if failed > 0:
    sys.exit(1)
PYEOF
    return $?
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

echo "============================================"
echo " UI Key Binding — Acceptance Test Suite"
echo "============================================"
echo "Timestamp: $(date)"
echo ""

# Check sniffer binary
if [ ! -x "$SNIFFER" ]; then
    echo -e "${RED}Error: sniffer binary not found. Run 'make' first.${NC}"
    exit 1
fi

# Check test pcap
if [ ! -f "$TEST_PCAP" ]; then
    echo -e "${YELLOW}Generating test pcap...${NC}"
    python3 /tmp/gen_test_pcap.py
fi

# ── Part A: Static ──
test_ac1_static
test_ac2_static
test_ac3_static
test_ac4_static
test_hotkey_hint

echo ""
echo -e "  ─── Static Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC} (of $TOTAL checks)"

STATIC_FAIL=$FAIL

# ── Part B: Runtime ──
run_pexpect_test
RUNTIME_RET=$?

# ── Final Summary ──
echo ""
echo "============================================"
echo " FINAL SUMMARY"
echo "============================================"
echo -e " Static checks:  ${GREEN}$((TOTAL - STATIC_FAIL)) passed${NC}, ${RED}$STATIC_FAIL failed${NC}"
if [ $RUNTIME_RET -eq 0 ]; then
    echo -e " Runtime tests:  ${GREEN}PASSED${NC}"
else
    echo -e " Runtime tests:  ${RED}FAILED${NC}"
fi

TOTAL_FAIL=$((STATIC_FAIL + (RUNTIME_RET != 0 ? 1 : 0)))
if [ $TOTAL_FAIL -eq 0 ]; then
    echo -e "\n${GREEN}═══ ALL ACCEPTANCE TESTS PASSED ═══${NC}"
    exit 0
else
    echo -e "\n${RED}═══ SOME TESTS FAILED ($TOTAL_FAIL) ═══${NC}"
    exit 1
fi
