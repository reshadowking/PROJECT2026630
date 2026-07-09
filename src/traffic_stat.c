<<<<<<< HEAD
/*
 * traffic_stat.c — 流量统计模块
 *
 * 功能:
 *   1. 全局协议分布统计 (TCP/UDP/ICMP/HTTP/DNS 报文数、总字节数)
 *   2. 五元组流量流水线 (per-flow 报文数/字节数)
 *   3. 定时输出 (文本模式) 与流回收
 *
 * 架构:
 *   - 256 分桶锁 (bucket_mutex) 降低多线程竞争
 *   - 原子操作更新全局统计计数器
 *   - 预分配空闲链表 (freelist) 减少 malloc/free 开销
 */

#include "common.h"
#include "traffic_stat.h"
#include "tcp_reassemble.h"
extern int use_ui;

traffic_stat g_stat = {0};

/* per-bucket mutexes — 大幅降低多 parser worker 竞争 */
static pthread_mutex_t bucket_mutex[FLOW_HASH_SIZE];
flow_stat_entry *flow_hash[FLOW_HASH_SIZE] = {NULL};

static pthread_t stat_tid;
static volatile int stat_running = 1;
static void *stat_loop(void *arg);

/* ── lock-free freelist ── */
static flow_stat_entry *g_flow_freelist = NULL;
static pthread_mutex_t freelist_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_flow_alloc_cnt = 0;
static unsigned int g_flow_free_cnt = 0;

#define FLOW_PREALLOC 8192

/*
 * flow_freelist_prealloc — 预分配流统计条目
 */
static void flow_freelist_prealloc(void)
{
    for (int i = 0; i < FLOW_PREALLOC; i++) {
        flow_stat_entry *e = (flow_stat_entry *)malloc(sizeof(flow_stat_entry));
        if (!e) break;
        e->next = g_flow_freelist;
        g_flow_freelist = e;
    }
    LOG_INFO("flow_freelist pre-allocated %d entries", FLOW_PREALLOC);
}

/*
 * flow_entry_alloc — 从 freelist 分配一个条目
 */
static flow_stat_entry *flow_entry_alloc(void)
{
    pthread_mutex_lock(&freelist_mutex);
    if (g_flow_freelist) {
        flow_stat_entry *e = g_flow_freelist;
        g_flow_freelist = e->next;
        e->next = NULL;
        g_flow_alloc_cnt++;
        pthread_mutex_unlock(&freelist_mutex);
        return e;
    }
    g_flow_alloc_cnt++;
    pthread_mutex_unlock(&freelist_mutex);
    return (flow_stat_entry *)malloc(sizeof(flow_stat_entry));
}

/*
 * flow_entry_free — 释放一个条目回 freelist
 */
static void flow_entry_free(flow_stat_entry *e)
{
    pthread_mutex_lock(&freelist_mutex);
    e->next = g_flow_freelist;
    g_flow_freelist = e;
    g_flow_free_cnt++;
    pthread_mutex_unlock(&freelist_mutex);
}

/*
 * flow_freelist_destroy — 销毁 freelist
 */
static void flow_freelist_destroy(void)
{
    flow_stat_entry *e = g_flow_freelist;
    while (e) {
        flow_stat_entry *next = e->next;
        free(e);
        e = next;
    }
    g_flow_freelist = NULL;
    LOG_INFO("flow_freelist destroyed, alloc=%u free=%u", g_flow_alloc_cnt, g_flow_free_cnt);
}

/*
 * flow_hash_idx — 计算五元组的哈希桶索引
 *
 * 支持 IPv4 和 IPv6: IPv6 时额外 XOR 128 位地址。
 */
static unsigned int flow_hash_idx(const flow5_key *k)
{
    unsigned int h1 = k->sip ^ (k->dip << 13);
    unsigned int h2 = (k->sp << 8) ^ k->dp ^ k->proto;
    unsigned int h = h1 ^ (h2 >> 5);

    if (k->is_ipv6) {
        for (int i = 0; i < IPV6_LEN; i += 4) {
            unsigned int w = ((unsigned int)k->sip6[i]   << 24) |
                             ((unsigned int)k->sip6[i+1] << 16) |
                             ((unsigned int)k->sip6[i+2] << 8)  |
                             ((unsigned int)k->sip6[i+3]);
            h ^= w;
            w = ((unsigned int)k->dip6[i]   << 24) |
                ((unsigned int)k->dip6[i+1] << 16) |
                ((unsigned int)k->dip6[i+2] << 8)  |
                ((unsigned int)k->dip6[i+3]);
            h ^= (w << 7);
        }
    }
    h ^= h >> 16;
    return h % FLOW_HASH_SIZE;
}

/*
 * flow_key_equal — 比较两个 flow5_key 是否相等
 */
static int flow_key_equal(const flow5_key *a, const flow5_key *b)
{
    if (a->is_ipv6 != b->is_ipv6) return 0;
    if (a->sp != b->sp || a->dp != b->dp || a->proto != b->proto) return 0;
    if (a->is_ipv6) {
        return (memcmp(a->sip6, b->sip6, IPV6_LEN) == 0 &&
                memcmp(a->dip6, b->dip6, IPV6_LEN) == 0);
    }
    return (a->sip == b->sip && a->dip == b->dip);
}

/*
 * flow_stat_add — 添加或更新一个五元组流量统计条目
 *   key:    五元组 (IPv4 或 IPv6)
 *   pkt_len: 报文长度 (字节)
 */
void flow_stat_add(const flow5_key *key, int pkt_len)
{
    unsigned int idx = flow_hash_idx(key);

    pthread_mutex_lock(&bucket_mutex[idx]);

    flow_stat_entry *e = flow_hash[idx];
    while (e) {
        if (flow_key_equal(&e->key, key)) {
            e->pkt_cnt++;
            e->byte_cnt += (unsigned long)pkt_len;
            pthread_mutex_unlock(&bucket_mutex[idx]);
            return;
        }
        e = e->next;
    }

    flow_stat_entry *new_entry = flow_entry_alloc();
    if (!new_entry) {
        pthread_mutex_unlock(&bucket_mutex[idx]);
        return;
    }
    new_entry->key = *key;
    new_entry->pkt_cnt = 1;
    new_entry->byte_cnt = (unsigned long)pkt_len;
    new_entry->next = flow_hash[idx];
    flow_hash[idx] = new_entry;

    pthread_mutex_unlock(&bucket_mutex[idx]);
}

/*
 * print_all_flow_stat — 输出所有五元组流量统计 (文本模式)
 */
void print_all_flow_stat(void)
{
    /* lock all buckets for a consistent snapshot */
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        pthread_mutex_lock(&bucket_mutex[i]);
    }
    printf("-------- 五元组流量明细 --------\n");
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        flow_stat_entry *e = flow_hash[i];
        while (e) {
            if (e->key.is_ipv6) {
                char sip6_str[INET6_ADDRSTRLEN] = {0};
                char dip6_str[INET6_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET6, e->key.sip6, sip6_str, sizeof(sip6_str));
                inet_ntop(AF_INET6, e->key.dip6, dip6_str, sizeof(dip6_str));
                printf("[%s]:%u -> [%s]:%u proto=%d PKT:%u BYTES:%lu\n",
                       sip6_str, e->key.sp,
                       dip6_str, e->key.dp,
                       e->key.proto, e->pkt_cnt, e->byte_cnt);
            } else {
                struct in_addr sa, da;
                sa.s_addr = htonl(e->key.sip);
                da.s_addr = htonl(e->key.dip);
                printf("%s:%u -> %s:%u proto=%d PKT:%u BYTES:%lu\n",
                       inet_ntoa(sa), e->key.sp,
                       inet_ntoa(da), e->key.dp,
                       e->key.proto, e->pkt_cnt, e->byte_cnt);
            }
            e = e->next;
        }
    }
    printf("--------------------------------\n");
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        pthread_mutex_unlock(&bucket_mutex[i]);
    }
}

/*
 * flow_stat_clear_all — 清空所有流统计条目
 */
void flow_stat_clear_all(void)
{
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        pthread_mutex_lock(&bucket_mutex[i]);
    }
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        flow_stat_entry *e = flow_hash[i];
        while (e) {
            flow_stat_entry *next = e->next;
            flow_entry_free(e);
            e = next;
        }
        flow_hash[i] = NULL;
    }
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        pthread_mutex_unlock(&bucket_mutex[i]);
    }
}

/* ── 原子统计递增 ── */
void stat_inc_total(int byte) {
    __atomic_add_fetch(&g_stat.pkt_total, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_stat.byte_total, byte, __ATOMIC_RELAXED);
}
void stat_inc_tcp(void) {
    __atomic_add_fetch(&g_stat.pkt_tcp, 1, __ATOMIC_RELAXED);
}
void stat_inc_udp(void) {
    __atomic_add_fetch(&g_stat.pkt_udp, 1, __ATOMIC_RELAXED);
}
void stat_inc_icmp(void) {
    __atomic_add_fetch(&g_stat.pkt_icmp, 1, __ATOMIC_RELAXED);
}
void stat_inc_http(void) {
    __atomic_add_fetch(&g_stat.pkt_http, 1, __ATOMIC_RELAXED);
}
void stat_inc_dns(void) {
    __atomic_add_fetch(&g_stat.pkt_dns, 1, __ATOMIC_RELAXED);
}
void stat_inc_http_reassemble(void) {
    __atomic_add_fetch(&g_stat.pkt_http, 1, __ATOMIC_RELAXED);
}

/*
 * print_stat — 输出全局流量汇总
 */
void print_stat(void)
{
    printf("===== 全局流量汇总 =====\n");
    printf("TCP:%u UDP:%u ICMP:%u HTTP:%u DNS:%u TotalPkt:%u TotalByte:%lu\n",
           g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp, g_stat.pkt_http, g_stat.pkt_dns,
           g_stat.pkt_total, g_stat.byte_total);
    printf("========================\n");
    print_all_flow_stat();
}

/*
 * stat_loop — 统计线程工作循环
 *
 * 每 1s 输出文本统计 (非 UI 模式), 每 5s 触发流回收。
 */
static void *stat_loop(void *arg)
{
    (void)arg;
    int tick_cnt = 0;
    const int TICK_PER_SEC = 10;
    const int PRINT_INTERVAL = 1;
    while (stat_running) {
=======
#include "common.h"
#include "traffic_stat.h"
traffic_stat g_stat = {0};
pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flow_hash_mutex = PTHREAD_MUTEX_INITIALIZER;
// 五元组哈希存储数组
flow_stat_entry flow_hash[FLOW_HASH_SIZE] = {0};
static pthread_t stat_tid;
static int stat_running = 1;
static void *stat_loop(void *arg);

// 哈希简易取模
static unsigned int flow_hash_idx(const flow5_key *k) {
    unsigned int h = k->sip ^ k->dip ^ k->sp ^ k->dp ^ k->proto;
    return h % FLOW_HASH_SIZE;
}

// 新增/更新五元组流量
void flow_stat_add(const flow5_key *key, int pkt_len) {
    pthread_mutex_lock(&flow_hash_mutex);
    unsigned int idx = flow_hash_idx(key);
    flow_stat_entry *e = &flow_hash[idx];
    if (e->pkt_cnt == 0) {
        e->key = *key;
        e->pkt_cnt = 1;
        e->byte_cnt = pkt_len;
    } else {
        if (e->key.sip == key->sip && e->key.dip == key->dip &&
            e->key.sp == key->sp && e->key.dp == key->dp) {
            e->pkt_cnt++;
            e->byte_cnt += pkt_len;
        } else {
            e->key = *key;
            e->pkt_cnt = 1;
            e->byte_cnt = pkt_len;
        }
    }
    pthread_mutex_unlock(&flow_hash_mutex);
}

// 打印全部活跃五元组流量
void print_all_flow_stat() {
    pthread_mutex_lock(&flow_hash_mutex);
    printf("--------五元组流量明细--------\n");
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        flow_stat_entry *e = &flow_hash[i];
        if (e->pkt_cnt == 0) continue;
        printf("SIP:%u DIP:%u SP:%u DP:%u PKT:%u BYTES:%lu\n",
               e->key.sip, e->key.dip, e->key.sp, e->key.dp,
               e->pkt_cnt, e->byte_cnt);
    }
    printf("-----------------------------\n");
    pthread_mutex_unlock(&stat_mutex);
}

// 全局总统计接口
void stat_inc_total(int byte) {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_total++;
    g_stat.byte_total += byte;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_tcp() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_tcp++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_udp() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_udp++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_icmp() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_icmp++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_http() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_http++;
    pthread_mutex_unlock(&stat_mutex);
}
void stat_inc_dns() {
    pthread_mutex_lock(&stat_mutex);
    g_stat.pkt_dns++;
    pthread_mutex_unlock(&stat_mutex);
}

// 打印汇总统计 + 每条五元组流量
void print_stat() {
    pthread_mutex_lock(&stat_mutex);
    printf("===== 全局流量汇总 =====\n");
    printf("TCP:%d UDP:%d ICMP:%d HTTP:%d DNS:%d TotalPkt:%d TotalByte:%lu\n",
           g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp, g_stat.pkt_http, g_stat.pkt_dns,
           g_stat.pkt_total, g_stat.byte_total);
    printf("========================\n");
    pthread_mutex_unlock(&stat_mutex);
    print_all_flow_stat();
}

// 优化循环：每100ms检查退出标记，无长阻塞睡眠
void *stat_loop(void *arg) {
    (void)arg;
    int tick_cnt = 0;
    const int TICK_PER_SEC = 10;
    const int PRINT_INTERVAL = 5;
    while(stat_running) {
>>>>>>> f0af05853c426556dd630fdc472bd9d39aa22de9
        usleep(100000);
        if (!stat_running) break;
        tick_cnt++;
        if (tick_cnt >= TICK_PER_SEC * PRINT_INTERVAL) {
<<<<<<< HEAD
            if (!use_ui) {
                /* only print summary; full flow table is expensive (locks all buckets) */
                printf("===== 全局流量汇总 =====\n");
                printf("TCP:%u UDP:%u ICMP:%u HTTP:%u DNS:%u TotalPkt:%u TotalByte:%lu\n",
                       g_stat.pkt_tcp, g_stat.pkt_udp, g_stat.pkt_icmp,
                       g_stat.pkt_http, g_stat.pkt_dns,
                       g_stat.pkt_total, g_stat.byte_total);
                printf("========================\n");
            }
            tick_cnt = 0;
        }
        if (tick_cnt == TICK_PER_SEC * 5) {
            tcp_flow_reap();
        }
=======
            print_stat();
            tick_cnt = 0;
        }
>>>>>>> f0af05853c426556dd630fdc472bd9d39aa22de9
    }
    return NULL;
}

/*
 * stat_thread_start — 启动统计线程
 */
void stat_thread_start(void)
{
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        pthread_mutex_init(&bucket_mutex[i], NULL);
    }
    flow_freelist_prealloc();
    stat_running = 1;
    pthread_create(&stat_tid, NULL, stat_loop, NULL);
}

<<<<<<< HEAD
/*
 * stat_thread_stop — 停止统计线程并清理
 */
void stat_thread_stop(void)
{
=======
// 标准join，无np扩展函数
void stat_thread_stop() {
>>>>>>> f0af05853c426556dd630fdc472bd9d39aa22de9
    stat_running = 0;
    pthread_join(stat_tid, NULL);
    flow_stat_clear_all();
    flow_freelist_destroy();
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        pthread_mutex_destroy(&bucket_mutex[i]);
    }
}
