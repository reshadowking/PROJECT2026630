#include "common.h"
#include "traffic_stat.h"
extern int use_ui;

traffic_stat g_stat = {0};
pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flow_hash_mutex = PTHREAD_MUTEX_INITIALIZER;
flow_stat_entry flow_hash[FLOW_HASH_SIZE] = {0};
static pthread_t stat_tid;
static int stat_running = 1;
static void *stat_loop(void *arg);

/* ── Global loss-rate counters (updated by capture thread, read by UI/stat thread) ── */
volatile u_long g_pcap_recv   = 0;
volatile u_long g_pcap_drop   = 0;
volatile u_long g_pcap_ifdrop = 0;

static unsigned int flow_hash_idx(const flow5_key *k) {
    unsigned int h1 = k->sip ^ (k->dip << 13);
    unsigned int h2 = (k->sp << 8) ^ k->dp ^ k->proto;
    unsigned int h = h1 ^ (h2 >> 5);
    h ^= h >> 16;
    return h % FLOW_HASH_SIZE;
}

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
            /* Collision — replace with new flow (simple strategy for high-speed) */
            e->key = *key;
            e->pkt_cnt = 1;
            e->byte_cnt = pkt_len;
        }
    }
    pthread_mutex_unlock(&flow_hash_mutex);
}

void print_all_flow_stat() {
    pthread_mutex_lock(&flow_hash_mutex);
    printf("-------- Flow Details --------\n");
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        flow_stat_entry *e = &flow_hash[i];
        if (e->pkt_cnt == 0) continue;
        char sip_str[INET_ADDRSTRLEN], dip_str[INET_ADDRSTRLEN];
        struct in_addr sa, da;
        sa.s_addr = htonl(e->key.sip);
        da.s_addr = htonl(e->key.dip);
        inet_ntop(AF_INET, &sa, sip_str, sizeof(sip_str));
        inet_ntop(AF_INET, &da, dip_str, sizeof(dip_str));
        printf("%s:%u -> %s:%u proto=%u pkts=%u bytes=%lu\n",
               sip_str, e->key.sp,
               dip_str, e->key.dp,
               e->key.proto, e->pkt_cnt, e->byte_cnt);
    }
    printf("-----------------------------\n");
    pthread_mutex_unlock(&flow_hash_mutex);
}

/* ── Atomic stat increment helpers ── */

void stat_inc_total(int byte) {
    __atomic_add_fetch(&g_stat.pkt_total, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_stat.byte_total, byte, __ATOMIC_RELAXED);
}

void stat_inc_tcp() {
    __atomic_add_fetch(&g_stat.pkt_tcp, 1, __ATOMIC_RELAXED);
}

void stat_inc_udp() {
    __atomic_add_fetch(&g_stat.pkt_udp, 1, __ATOMIC_RELAXED);
}

void stat_inc_icmp() {
    __atomic_add_fetch(&g_stat.pkt_icmp, 1, __ATOMIC_RELAXED);
}

void stat_inc_http() {
    __atomic_add_fetch(&g_stat.pkt_http, 1, __ATOMIC_RELAXED);
}

void stat_inc_http_req() {
    __atomic_add_fetch(&g_stat.pkt_http_req, 1, __ATOMIC_RELAXED);
}

void stat_inc_http_resp() {
    __atomic_add_fetch(&g_stat.pkt_http_resp, 1, __ATOMIC_RELAXED);
}

void stat_inc_dns() {
    __atomic_add_fetch(&g_stat.pkt_dns, 1, __ATOMIC_RELAXED);
}

void stat_inc_http_reassemble() {
    __atomic_add_fetch(&g_stat.pkt_http, 1, __ATOMIC_RELAXED);
}

/* ── Read stats safely (snapshot for display) ── */
void stat_snapshot(traffic_stat *out) {
    out->pkt_tcp     = __atomic_load_n(&g_stat.pkt_tcp, __ATOMIC_RELAXED);
    out->pkt_udp     = __atomic_load_n(&g_stat.pkt_udp, __ATOMIC_RELAXED);
    out->pkt_icmp    = __atomic_load_n(&g_stat.pkt_icmp, __ATOMIC_RELAXED);
    out->pkt_http    = __atomic_load_n(&g_stat.pkt_http, __ATOMIC_RELAXED);
    out->pkt_http_req  = __atomic_load_n(&g_stat.pkt_http_req, __ATOMIC_RELAXED);
    out->pkt_http_resp = __atomic_load_n(&g_stat.pkt_http_resp, __ATOMIC_RELAXED);
    out->pkt_dns     = __atomic_load_n(&g_stat.pkt_dns, __ATOMIC_RELAXED);
    out->pkt_total   = __atomic_load_n(&g_stat.pkt_total, __ATOMIC_RELAXED);
    out->byte_total  = __atomic_load_n(&g_stat.byte_total, __ATOMIC_RELAXED);
}

void print_stat() {
    traffic_stat snap;
    stat_snapshot(&snap);
    printf("===== Global Traffic Summary =====\n");
    printf("TCP:%d UDP:%d ICMP:%d HTTP:%d(Req:%d Resp:%d) DNS:%d TotalPkt:%d TotalByte:%lu\n",
           snap.pkt_tcp, snap.pkt_udp, snap.pkt_icmp,
           snap.pkt_http, snap.pkt_http_req, snap.pkt_http_resp,
           snap.pkt_dns, snap.pkt_total, snap.byte_total);

    /* Loss rate from pcap stats */
    u_long recv = __atomic_load_n(&g_pcap_recv, __ATOMIC_RELAXED);
    u_long drop = __atomic_load_n(&g_pcap_drop, __ATOMIC_RELAXED);
    u_long ifdrop = __atomic_load_n(&g_pcap_ifdrop, __ATOMIC_RELAXED);
    if (recv + drop > 0) {
        double loss = (double)(drop + ifdrop) / (double)(recv + drop + ifdrop) * 100.0;
        printf("LossRate: %.2f%% (recv:%lu drop:%lu ifdrop:%lu)\n", loss, recv, drop, ifdrop);
    }
    printf("==================================\n");
    print_all_flow_stat();
}

void *stat_loop(void *arg) {
    (void)arg;
    int tick_cnt = 0;
    const int TICK_PER_SEC = 10;
    const int PRINT_INTERVAL = 1;
    while (stat_running) {
        usleep(100000);
        if (!stat_running) break;
        tick_cnt++;
        if (tick_cnt >= TICK_PER_SEC * PRINT_INTERVAL) {
            if (!use_ui) {
                print_stat();
            }
            tick_cnt = 0;
        }
    }
    return NULL;
}

void stat_thread_start() {
    stat_running = 1;
    if (pthread_create(&stat_tid, NULL, stat_loop, NULL) != 0) {
        stat_running = 0;
    }
}

void stat_thread_stop() {
    if (!stat_running) return;
    stat_running = 0;
    pthread_join(stat_tid, NULL);
}
