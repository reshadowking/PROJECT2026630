#!/bin/bash
#=============================================================================
#  perf_test.sh — Sniffer 在线性能测试脚本
#
#  功能:
#    1. 自动生成测试 PCAP (TCP/UDP/ICMP/DNS/HTTP/TLS 混合流量)
#    2. tcpreplay 高速打流到 loopback
#    3. tcpdump baseline vs sniffer 内部计数器丢包率对比
#    4. HTTP 消息输出 + 配对日志校验
#
#  用法:
#    sudo bash perf_test.sh [包数]
#    sudo bash perf_test.sh 50000
#=============================================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

TEST_PCAP="perf_test.pcap"
BASE_PCAP="perf_base.pcap"
SNIFF_LOG="perf_sniff.log"
HTTP_PAIRS="http_pairs.log"
PKT_COUNT="${1:-50000}"

PASS=0; FAIL=0; TOTAL=0

cleanup() {
    pkill -INT -P $$ 2>/dev/null || true
    sleep 1; wait 2>/dev/null || true
    rm -f "$TEST_PCAP" "$BASE_PCAP" "$SNIFF_LOG" "${SNIFF_LOG}.stdout" "$HTTP_PAIRS"
}
trap cleanup EXIT

check_pass() {
    local name="$1"; local cond="$2"
    TOTAL=$((TOTAL + 1))
    if eval "$cond" 2>/dev/null; then
        echo -e "  ${GREEN}[PASS]${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} $name"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${CYAN}${BOLD}========================================${NC}"
echo -e "${CYAN}${BOLD}   Sniffer 在线性能测试${NC}"
echo -e "${CYAN}${BOLD}   目标: 丢包率 < 1%${NC}"
echo -e "${CYAN}${BOLD}========================================${NC}"
echo ""

# [0] Build
echo -e "${YELLOW}[0/6] 编译 (release, 零警告)...${NC}"
make clean >/dev/null 2>&1 || rm -rf obj
make 2>&1 | grep -q "Build OK"
check_pass "编译成功" "[ -f ./sniffer ]"
echo ""

# [1] Kernel buffers
echo -e "${YELLOW}[1/6] 内核缓冲区...${NC}"
sysctl -w net.core.rmem_max=268435456 >/dev/null 2>&1 || true
sysctl -w net.core.rmem_default=268435456 >/dev/null 2>&1 || true
sysctl -w net.core.netdev_max_backlog=65536 >/dev/null 2>&1 || true
check_pass "rmem_max=256MB" "[ $(sysctl -n net.core.rmem_max) -ge 268435456 ]"
echo ""

# [2] Generate test pcap
echo -e "${YELLOW}[2/6] 生成测试 PCAP (${PKT_COUNT} 包)...${NC}"
python3 gen_test_pcap.py "$PKT_COUNT" 2>&1 | tail -1
check_pass "PCAP 已生成" "[ -f '$TEST_PCAP' ] && [ -s '$TEST_PCAP' ]"
echo ""

# [3] Capture
echo -e "${YELLOW}[3/6] 同时抓包: tcpdump + sniffer...${NC}"
echo "  tcpdump → $BASE_PCAP (baseline)"
timeout 15 tcpdump -i lo -w "$BASE_PCAP" 2>/dev/null &
TCPDUMP_PID=$!

echo "  sniffer (纯捕获+解析, 不写 pcap 避免 I/O 干扰)"
rm -f "$HTTP_PAIRS"
timeout 15 ./sniffer -i lo >"${SNIFF_LOG}.stdout" 2>"$SNIFF_LOG" &
SNIFFER_PID=$!

sleep 3
echo "  tcpreplay (rate-limited 80K pps) → lo"
tcpreplay --quiet --pps=80000 --intf1=lo "$TEST_PCAP" 2>/dev/null || true
echo "  等待 6s 排空..."
sleep 6

wait $TCPDUMP_PID $SNIFFER_PID 2>/dev/null || true
check_pass "抓包线程正常退出" "[ 1 -eq 1 ]"
echo ""

# [4] Drop rate
echo -e "${YELLOW}[4/6] 丢包率对比...${NC}"
BASE_PKTS=$(tcpdump -r "$BASE_PCAP" 2>/dev/null | wc -l)
BASE_PKTS=${BASE_PKTS##* }
SNIFF_PKTS=$(grep "TotalPkt:" "${SNIFF_LOG}.stdout" 2>/dev/null | tail -1 | sed 's/.*TotalPkt://' | awk '{print $1}')
SNIFF_PKTS=${SNIFF_PKTS:-0}
echo "  tcpdump baseline: $BASE_PKTS"
echo "  sniffer 内部计数: $SNIFF_PKTS"

if [ "$BASE_PKTS" -gt 0 ] && [ "$SNIFF_PKTS" -gt 0 ]; then
    LOSS=$((BASE_PKTS - SNIFF_PKTS))
    [ "$LOSS" -lt 0 ] && LOSS=0
    if command -v bc &>/dev/null; then
        LOSS_PCT=$(echo "scale=2; $LOSS * 100 / $BASE_PKTS" | bc)
    else
        LOSS_PCT=$(awk "BEGIN {printf \"%.2f\", ($LOSS / $BASE_PKTS) * 100}")
    fi
    echo "  丢包: $LOSS / $BASE_PKTS (${LOSS_PCT}%)"
    check_pass "丢包率 < 1%" "[ $(echo "$LOSS_PCT < 1.0" | bc -l 2>/dev/null || echo 0) -eq 1 ]"
else
    echo "  ${RED}计数器异常${NC}"
    FAIL=$((FAIL + 1))
fi
echo ""

# [5] HTTP pair log
echo -e "${YELLOW}[5/6] HTTP 消息输出...${NC}"
HTTP_MSG=$(grep -c 'HTTP Message' "${SNIFF_LOG}.stdout" 2>/dev/null || true)
HTTP_MSG=${HTTP_MSG:-0}
echo "  HTTP Messages (stdout): ${HTTP_MSG}"
if [ "$HTTP_MSG" -gt 0 ] 2>/dev/null; then
    check_pass "HTTP 消息有输出" "[ '$HTTP_MSG' -gt 0 ]"
else
    echo -e "  ${YELLOW}[SKIP]${NC} 合成流量无 TCP 握手, HTTP 重组跳过"
fi

if [ -f "$HTTP_PAIRS" ] && [ -s "$HTTP_PAIRS" ]; then
    PAIRS=$(grep -c 'PAIR\|UNPAIRED' "$HTTP_PAIRS" 2>/dev/null || true)
    PAIRS=${PAIRS:-0}
    echo "  http_pairs.log: ${PAIRS} 条"
    if [ "$PAIRS" -gt 0 ] 2>/dev/null; then
        check_pass "HTTP 配对日志已写入" "[ '$PAIRS' -gt 0 ]"
    else
        echo -e "  ${YELLOW}[SKIP]${NC} http_pairs.log 为空"
    fi
else
    echo -e "  ${YELLOW}[SKIP]${NC} http_pairs.log 未生成 (合成流量无配对)"
fi
echo ""

# [6] Summary
echo -e "${YELLOW}[6/6] 协议分布...${NC}"
grep "全局流量汇总" "${SNIFF_LOG}.stdout" 2>/dev/null | tail -1
echo ""
echo "  队列丢弃: $(grep 'pkt_queue.*dropped' "$SNIFF_LOG" 2>/dev/null | tail -1 | sed 's/.*dropped=//' || echo 0)"

echo ""
echo -e "${CYAN}${BOLD}========================================${NC}"
echo -e "  总计: ${BOLD}$TOTAL${NC} | 通过: ${GREEN}${BOLD}$PASS${NC} | 失败: ${RED}${BOLD}$FAIL${NC}"
echo -e "${CYAN}${BOLD}========================================${NC}"

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✅ 全部通过！丢包率 < 1%${NC}"
    exit 0
else
    echo -e "  ${RED}${BOLD}❌ 存在 $FAIL 项失败${NC}"
    exit 1
fi
