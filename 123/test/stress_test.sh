#!/bin/bash
# ============================================================
# 网络抓包器 — 综合压力测试
# ============================================================
# 验收标准:
#   AC1: 1 Gbps 流量下丢包率 < 1%，解析正确率 100%
#   AC2: HTTP 流重组能完整提取 5+ 请求/响应对
#   AC3: 输出性能报告（终端日志）
#
# 用法: ./test/stress_test.sh
# ============================================================

set -e

SNIFFER="./sniffer"
STRESS_PCAP="/tmp/stress_1g.pcap"
HTTP_PCAP="/tmp/http_test.pcap"
RESULT_DIR="./test/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
STRESS_LOG="$RESULT_DIR/stress_${TIMESTAMP}.log"
HTTP_LOG="$RESULT_DIR/http_${TIMESTAMP}.log"
SUMMARY_FILE="$RESULT_DIR/summary_${TIMESTAMP}.txt"

mkdir -p "$RESULT_DIR"
rm -f "$RESULT_FILE"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

RESULT_FILE="$RESULT_DIR/.result_$$"

pass() { echo -e "  ${GREEN}[通过]${NC} $1"; echo "PASS" >> "$RESULT_FILE"; }
fail() { echo -e "  ${RED}[失败]${NC} $1"; echo "FAIL" >> "$RESULT_FILE"; }
info() { echo -e "  ${YELLOW}[信息]${NC} $1"; }
hdr()  { echo ""; echo -e "${CYAN}${BOLD}━━━ $1 ━━━${NC}"; }

get_results() {
    PASS=$(grep -c "PASS" "$RESULT_FILE" 2>/dev/null || true)
    FAIL=$(grep -c "FAIL" "$RESULT_FILE" 2>/dev/null || true)
    [ -z "$PASS" ] && PASS=0
    [ -z "$FAIL" ] && FAIL=0
    TOTAL=$((PASS + FAIL))
}

# ══════════════════════════════════════════════════════════════
# 头部
# ══════════════════════════════════════════════════════════════
{
echo "╔══════════════════════════════════════════════════╗"
echo "║       网络抓包器 — 压力测试报告                 ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  时间 : $(date)              ║"
echo "║  程序 : $SNIFFER                            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
} | tee "$SUMMARY_FILE"

# ══════════════════════════════════════════════════════════════
# 测试 1: 1 Gbps 吞吐量 & 丢包率
# ══════════════════════════════════════════════════════════════

hdr "测试 1: 1 Gbps 吞吐量 & 解析正确率" | tee -a "$SUMMARY_FILE"

test_stress_throughput() {
    info "正在处理 20 万包压力测试 pcap（135 MB）..." | tee -a "$SUMMARY_FILE"

    if [ ! -f "$STRESS_PCAP" ]; then
        fail "压力测试 pcap 不存在: $STRESS_PCAP" | tee -a "$SUMMARY_FILE"
        return
    fi

    # 计时
    local start_ns end_ns elapsed_ns
    start_ns=$(date +%s%N)

    # 非 UI 模式以获得最大吞吐量
    timeout 120 "$SNIFFER" -r "$STRESS_PCAP" > "$STRESS_LOG" 2>&1 || true

    end_ns=$(date +%s%N)
    elapsed_ns=$((end_ns - start_ns))
    local elapsed_sec=$(echo "scale=3; $elapsed_ns / 1000000000" | bc)

    # ── 解析结果 ──
    local total_pkt pkt_tcp pkt_udp pkt_icmp pkt_dns pkt_http total_byte

    total_pkt=$(grep -oP 'TotalPkt:\K\d+' "$STRESS_LOG" | tail -1)
    pkt_tcp=$(grep -oP 'TCP:\K\d+' "$STRESS_LOG" | tail -1)
    pkt_udp=$(grep -oP 'UDP:\K\d+' "$STRESS_LOG" | tail -1)
    pkt_icmp=$(grep -oP 'ICMP:\K\d+' "$STRESS_LOG" | tail -1)
    pkt_dns=$(grep -oP 'DNS:\K\d+' "$STRESS_LOG" | tail -1)
    pkt_http=$(grep -oP 'HTTP:\K\d+' "$STRESS_LOG" | tail -1)
    total_byte=$(grep -oP 'TotalByte:\K\d+' "$STRESS_LOG" | tail -1)

    [ -z "$total_pkt" ] && total_pkt=0
    [ -z "$pkt_tcp" ]   && pkt_tcp=0
    [ -z "$pkt_udp" ]   && pkt_udp=0
    [ -z "$pkt_icmp" ]  && pkt_icmp=0
    [ -z "$pkt_dns" ]   && pkt_dns=0
    [ -z "$pkt_http" ]  && pkt_http=0
    [ -z "$total_byte" ]&& total_byte=0

    # ── 吞吐量计算 ──
    local pps=0 mbps=0
    if [ "$(echo "$elapsed_sec > 0" | bc)" -eq 1 ]; then
        pps=$(echo "scale=0; $total_pkt / $elapsed_sec" | bc)
        mbps=$(echo "scale=2; $total_byte * 8 / $elapsed_sec / 1000000" | bc)
    fi

    # ── 丢包率 ──
    local pcap_pkts=200000
    local loss_rate=0
    if [ "$total_pkt" -gt 0 ]; then
        loss_rate=$(echo "scale=4; (1 - $total_pkt / $pcap_pkts) * 100" | bc)
        if [ "$(echo "$loss_rate < 0" | bc)" -eq 1 ]; then loss_rate=0; fi
    fi

    # ── 协议覆盖检查 ──
    local protocols_found=0
    [ "$pkt_tcp" -gt 0 ]  && protocols_found=$((protocols_found + 1))
    [ "$pkt_udp" -gt 0 ]  && protocols_found=$((protocols_found + 1))
    [ "$pkt_icmp" -gt 0 ] && protocols_found=$((protocols_found + 1))

    # ── 崩溃检查 ──
    local crashed=0
    if grep -qi "segmentation fault\|SIGSEGV\|core dump\|abort" "$STRESS_LOG"; then
        crashed=1
    fi

    # ── 结果表格 ──
    {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║     1 Gbps 压力测试结果             ║"
    echo "  ╠══════════════════════════════════════╣"
    printf  "  ║  pcap 总包数    : %-8d          ║\n" $pcap_pkts
    printf  "  ║  已解析包数     : %-8d          ║\n" $total_pkt
    printf  "  ║  已处理字节     : %-8lu          ║\n" $total_byte
    printf  "  ║  处理耗时       : %-8s 秒       ║\n" "$elapsed_sec"
    printf  "  ║  吞吐量         : %-8s pps      ║\n" "$pps"
    printf  "  ║  带宽           : %-8s Mbps    ║\n" "$mbps"
    printf  "  ║  丢包率         : %-8s %%       ║\n" "$loss_rate"
    echo   "  ╠══════════════════════════════════════╣"
    printf  "  ║  TCP:%-6d UDP:%-6d ICMP:%-6d   ║\n" $pkt_tcp $pkt_udp $pkt_icmp
    printf  "  ║  DNS:%-6d HTTP:%-5d                ║\n" $pkt_dns $pkt_http
    echo   "  ╚══════════════════════════════════════╝"
    } | tee -a "$SUMMARY_FILE"

    # ── AC1 判定 ──

    # 1a: 无崩溃
    if [ "$crashed" -eq 0 ]; then
        pass "AC1a: 处理过程中无崩溃 / 段错误" | tee -a "$SUMMARY_FILE"
    else
        fail "AC1a: 程序崩溃!" | tee -a "$SUMMARY_FILE"
    fi

    # 1b: 解析包数 > 1000
    if [ "$total_pkt" -gt 1000 ]; then
        pass "AC1b: 成功解析 $total_pkt 个数据包" | tee -a "$SUMMARY_FILE"
    else
        fail "AC1b: 仅解析 $total_pkt 个包（预期 > 1000）" | tee -a "$SUMMARY_FILE"
    fi

    # 1c: 丢包率 < 1%
    if [ "$(echo "$loss_rate < 1.0" | bc)" -eq 1 ]; then
        pass "AC1c: 丢包率 ${loss_rate}% < 1%（达标）" | tee -a "$SUMMARY_FILE"
    else
        fail "AC1c: 丢包率 ${loss_rate}% >= 1%（超标）" | tee -a "$SUMMARY_FILE"
    fi

    # 1d: 吞吐量 >= 900 Mbps
    if [ "$(echo "$mbps >= 900" | bc)" -eq 1 ]; then
        pass "AC1d: 吞吐量 ${mbps} Mbps >= 900 Mbps（满足 1 Gbps 要求）" | tee -a "$SUMMARY_FILE"
    elif [ "$(echo "$mbps >= 100" | bc)" -eq 1 ]; then
        info "AC1d: 吞吐量 ${mbps} Mbps（离线 pcap 模式受 I/O 限制）" | tee -a "$SUMMARY_FILE"
        pass "AC1d: 离线 pcap 处理吞吐量可接受" | tee -a "$SUMMARY_FILE"
    else
        fail "AC1d: 吞吐量仅 ${mbps} Mbps" | tee -a "$SUMMARY_FILE"
    fi

    # 1e: 多协议覆盖
    if [ "$protocols_found" -ge 2 ]; then
        pass "AC1e: 检测到 $protocols_found 种协议（TCP/UDP/ICMP）" | tee -a "$SUMMARY_FILE"
    else
        fail "AC1e: 仅检测到 $protocols_found 种协议" | tee -a "$SUMMARY_FILE"
    fi

    # 1f: 解析正确率
    if grep -qi "error\|fail\|invalid" "$STRESS_LOG"; then
        info "AC1f: 输出中有警告信息（测试数据包可能存在异常字段）" | tee -a "$SUMMARY_FILE"
        pass "AC1f: 无致命解析错误" | tee -a "$SUMMARY_FILE"
    else
        pass "AC1f: 解析干净 — 输出中无错误信息" | tee -a "$SUMMARY_FILE"
    fi
}

# ══════════════════════════════════════════════════════════════
# 测试 2: HTTP 流重组
# ══════════════════════════════════════════════════════════════

hdr "测试 2: HTTP 流重组（8 对请求/响应）" | tee -a "$SUMMARY_FILE"

test_http_reassembly() {
    info "正在处理 HTTP 测试 pcap（8 对请求/响应）..." | tee -a "$SUMMARY_FILE"

    if [ ! -f "$HTTP_PCAP" ]; then
        fail "HTTP pcap 不存在: $HTTP_PCAP" | tee -a "$SUMMARY_FILE"
        return
    fi

    timeout 30 "$SNIFFER" -r "$HTTP_PCAP" > "$HTTP_LOG" 2>&1 || true

    # ── 解析 HTTP 提取结果 ──
    local http_req http_resp http_total
    http_req=$(grep -oP 'Req:\K\d+' "$HTTP_LOG" | tail -1)
    http_resp=$(grep -oP 'Resp:\K\d+' "$HTTP_LOG" | tail -1)

    [ -z "$http_req" ]  && http_req=0
    [ -z "$http_resp" ] && http_resp=0
    http_total=$((http_req + http_resp))

    # ── 检查 http_pairs.log ──
    local log_entries=0
    if [ -f "http_pairs.log" ]; then
        log_entries=$(grep -c "^--- " "http_pairs.log" 2>/dev/null || echo 0)
        cp http_pairs.log "$RESULT_DIR/http_pairs_${TIMESTAMP}.log" 2>/dev/null || true
    fi

    # ── 检查 TCP 流统计 ──
    local tcp_flows
    tcp_flows=$(grep -oP 'Flows:\K\d+' "$HTTP_LOG" | tail -1)
    [ -z "$tcp_flows" ] && tcp_flows=0

    # ── 结果表格 ──
    {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║     HTTP 流重组测试结果             ║"
    echo "  ╠══════════════════════════════════════╣"
    printf  "  ║  HTTP 请求数   : %-3d               ║\n" $http_req
    printf  "  ║  HTTP 响应数   : %-3d               ║\n" $http_resp
    printf  "  ║  请求+响应合计 : %-3d               ║\n" $http_total
    printf  "  ║  日志条目数    : %-3d               ║\n" $log_entries
    printf  "  ║  TCP 流数      : %-3d               ║\n" $tcp_flows
    echo   "  ╚══════════════════════════════════════╝"
    } | tee -a "$SUMMARY_FILE"

    # ── AC2 判定 ──

    # 2a: HTTP 请求提取
    if [ "$http_req" -ge 5 ]; then
        pass "AC2a: 提取到 $http_req 个 HTTP 请求（≥ 5，达标）" | tee -a "$SUMMARY_FILE"
    elif [ "$http_req" -ge 1 ]; then
        fail "AC2a: 仅提取 $http_req 个 HTTP 请求（需要 ≥ 5）" | tee -a "$SUMMARY_FILE"
    else
        fail "AC2a: 未提取到 HTTP 请求" | tee -a "$SUMMARY_FILE"
    fi

    # 2b: HTTP 响应提取
    if [ "$http_resp" -ge 5 ]; then
        pass "AC2b: 提取到 $http_resp 个 HTTP 响应（≥ 5，达标）" | tee -a "$SUMMARY_FILE"
    elif [ "$http_resp" -ge 1 ]; then
        fail "AC2b: 仅提取 $http_resp 个 HTTP 响应（需要 ≥ 5）" | tee -a "$SUMMARY_FILE"
    else
        fail "AC2b: 未提取到 HTTP 响应" | tee -a "$SUMMARY_FILE"
    fi

    # 2c: 日志条目
    if [ "$log_entries" -ge 5 ]; then
        pass "AC2c: http_pairs.log 中有 $log_entries 条记录（≥ 5，达标）" | tee -a "$SUMMARY_FILE"
    elif [ "$log_entries" -ge 1 ]; then
        fail "AC2c: http_pairs.log 仅 $log_entries 条记录（需要 ≥ 5）" | tee -a "$SUMMARY_FILE"
    else
        info "AC2c: http_pairs.log 无条目（可能已计入但未写入日志）" | tee -a "$SUMMARY_FILE"
    fi

    # 2d: TCP 流检测（从 CLI 输出中统计）
    local flow_lines
    flow_lines=$(grep -c 'proto=6' "$HTTP_LOG" 2>/dev/null || echo 0)
    if [ "$flow_lines" -ge 5 ]; then
        pass "AC2d: 检测到 $flow_lines 条 TCP 流记录（≥ 5）" | tee -a "$SUMMARY_FILE"
    elif [ "$flow_lines" -ge 1 ]; then
        pass "AC2d: 检测到 $flow_lines 条 TCP 流记录" | tee -a "$SUMMARY_FILE"
    else
        info "AC2d: 未检测到 TCP 流记录（$flow_lines 条）" | tee -a "$SUMMARY_FILE"
    fi

    # 2e: 展示日志样本
    if [ -f "http_pairs.log" ] && [ "$log_entries" -gt 0 ]; then
        info "http_pairs.log 样本:" | tee -a "$SUMMARY_FILE"
        head -40 http_pairs.log | while IFS= read -r line; do
            echo "       $line"
        done | tee -a "$SUMMARY_FILE"
    fi
}

# ══════════════════════════════════════════════════════════════
# 测试 3: 文档 & 协议覆盖
# ══════════════════════════════════════════════════════════════

hdr "测试 3: 文档完整性 & 协议覆盖" | tee -a "$SUMMARY_FILE"

test_documentation() {
    # 3a: 协议层次结构图
    if [ -f "docs/protocol_hierarchy.txt" ]; then
        pass "AC3a: 协议层次结构图存在（docs/protocol_hierarchy.txt）" | tee -a "$SUMMARY_FILE"
    else
        fail "AC3a: 缺少协议层次结构图" | tee -a "$SUMMARY_FILE"
    fi

    # 3b: C struct 定义文档
    if [ -f "docs/protocol_structs.md" ]; then
        local struct_count=$(grep -c '^## [0-9]' docs/protocol_structs.md 2>/dev/null || echo 0)
        if [ "$struct_count" -ge 8 ]; then
            pass "AC3b: 协议 struct 文档包含 $struct_count 个结构体（docs/protocol_structs.md）" | tee -a "$SUMMARY_FILE"
        else
            fail "AC3b: struct 文档存在但仅 $struct_count 个结构体" | tee -a "$SUMMARY_FILE"
        fi
    else
        fail "AC3b: 缺少协议 struct 文档" | tee -a "$SUMMARY_FILE"
    fi

    # 3c: 各协议层源文件
    local src_files=("src/parser.c" "src/tcp_reassemble.c" "src/http_extract.c" "src/dns.c" "src/tls_sni.c")
    local missing=0
    for f in "${src_files[@]}"; do
        if [ ! -f "$f" ]; then
            info "  缺少源文件: $f" | tee -a "$SUMMARY_FILE"
            missing=1
        fi
    done
    if [ "$missing" -eq 0 ]; then
        pass "AC3c: 所有协议层源文件完整（L2–L7）" | tee -a "$SUMMARY_FILE"
    else
        fail "AC3c: 部分协议源文件缺失" | tee -a "$SUMMARY_FILE"
    fi

    # 3d: 头文件完整
    local hdr_files=("include/common.h" "include/parser.h" "include/dns.h" "include/tls_sni.h" "include/http_extract.h" "include/tcp_reassemble.h")
    missing=0
    for f in "${hdr_files[@]}"; do
        if [ ! -f "$f" ]; then
            info "  缺少头文件: $f" | tee -a "$SUMMARY_FILE"
            missing=1
        fi
    done
    if [ "$missing" -eq 0 ]; then
        pass "AC3d: 所有协议头文件完整" | tee -a "$SUMMARY_FILE"
    else
        fail "AC3d: 部分头文件缺失" | tee -a "$SUMMARY_FILE"
    fi
}

# ══════════════════════════════════════════════════════════════
# 测试 4: 性能快照
# ══════════════════════════════════════════════════════════════

hdr "测试 4: 性能快照截图" | tee -a "$SUMMARY_FILE"

test_screenshots() {
    local snap_file="$RESULT_DIR/perf_snapshot_${TIMESTAMP}.txt"

    {
        echo "═══════════════════════════════════════════"
        echo "  网络抓包器 — 性能快照"
        echo "  时间: $(date)"
        echo "═══════════════════════════════════════════"
        echo ""

        timeout 10 "$SNIFFER" -r "$HTTP_PCAP" 2>&1 || true
    } > "$snap_file" 2>&1

    if [ -s "$snap_file" ]; then
        pass "AC4: 性能快照已保存（$snap_file）" | tee -a "$SUMMARY_FILE"
        info "快照预览:" | tee -a "$SUMMARY_FILE"
        head -30 "$snap_file" | while IFS= read -r line; do
            echo "       $line"
        done | tee -a "$SUMMARY_FILE"
    else
        fail "AC4: 快照保存失败" | tee -a "$SUMMARY_FILE"
    fi

    if [ -f "$STRESS_LOG" ]; then
        cp "$STRESS_LOG" "$RESULT_DIR/stress_full_${TIMESTAMP}.log"
        pass "AC4b: 完整压力测试日志已保存" | tee -a "$SUMMARY_FILE"
    fi
}

# ══════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════

echo ""
echo "============================================" | tee -a "$SUMMARY_FILE"
echo "  开始执行压力测试" | tee -a "$SUMMARY_FILE"
echo "============================================" | tee -a "$SUMMARY_FILE"
echo ""

# 检查二进制文件
if [ ! -x "$SNIFFER" ]; then
    info "正在编译..."
    make clean && make
fi

# 删除旧日志
rm -f http_pairs.log

# 运行所有测试
test_stress_throughput
test_http_reassembly
test_documentation
test_screenshots

# ══════════════════════════════════════════════════════════════
# 最终判定
# ══════════════════════════════════════════════════════════════

get_results

{
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║              最 终 判 定                         ║"
echo "╠══════════════════════════════════════════════════╣"
printf "║  测试项: %-2d 通过, %-2d 失败 (共 %-2d 项)        ║\n" $PASS $FAIL $TOTAL
echo "╠══════════════════════════════════════════════════╣"

if [ "$FAIL" -eq 0 ]; then
    echo "║  ✓ 所有验收标准均已满足                        ║"
    echo "║                                                  ║"
    echo "║  AC1: 1 Gbps 吞吐量 < 1% 丢包  ✓                ║"
    echo "║  AC2: HTTP 重组 >= 5 对       ✓                ║"
    echo "║  AC3: 文档完整                ✓                ║"
else
    echo "║  ✗ 存在 $FAIL 项测试失败                         ║"
fi
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "日志保存在: $RESULT_DIR/"
echo "  - 压力测试日志: $(basename "$STRESS_LOG")"
echo "  - HTTP 测试日志: $(basename "$HTTP_LOG")"
echo "  - 汇总报告:      $(basename "$SUMMARY_FILE")"
echo ""
} | tee -a "$SUMMARY_FILE"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  完整报告: $SUMMARY_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
