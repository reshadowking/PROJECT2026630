/*
 * capture.c — 抓包引擎核心模块
 *
 * 功能:
 *   1. libpcap 实时抓包 (支持混杂模式、BPF 过滤、大内核缓冲区)
 *   2. 离线 pcap 文件回放
 *   3. 抓包线程: pcap_dispatch 批量采集 → 直接写 pcap dump →
 *      trylock 推入解析队列 → 推入 UI 环形缓冲区
 *   4. 解析器工作线程池
 *   5. 丢包统计
 *
 * 架构设计:
 *   - 单生产者 (capture_loop) → 多消费者 (parser_worker × N)
 *   - pkt_queue 使用 trylock 非阻塞推送，避免抓包线程被慢解析器阻塞
 *   - dump 内联在 capture_loop 中 (直接 pcap_dump)，无需额外线程
 */

#include "common.h"
#include "capture.h"
#include "parser.h"
#include "ui.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

pcap_t *g_handle = NULL;
pcap_dumper_t *g_dumper = NULL;
extern volatile int capture_pause;
extern volatile int exit_flag;

static int g_is_offline = 0;  /* 1 = reading from pcap file, 0 = live capture */

pkt_queue g_pkt_queue;
ui_ring g_ui_ring;

static pthread_t g_capture_tid;
static pthread_t g_parser_tids[PARSER_WORKERS];
static int g_capture_running = 0;
static int g_parsers_running = 0;
static volatile unsigned long g_dropped = 0;   /* 内部队列丢弃计数 */

/* ──────────────────────────────────────────────
 *  capture batch context — 批量抓包上下文
 * ────────────────────────────────────────────── */
typedef struct {
    pkt_entry *batch_buf;
    int batch_count;
    int batch_capacity;
} capture_batch_ctx;

/*
 * pkt_callback — pcap_dispatch 回调函数
 *   将抓到的包写入批量缓冲区
 */
static void pkt_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
    capture_batch_ctx *ctx = (capture_batch_ctx *)user;
    if (ctx->batch_count >= ctx->batch_capacity) return;

    pkt_entry *pkt = &ctx->batch_buf[ctx->batch_count];
    memcpy(&pkt->hdr, hdr, sizeof(struct pcap_pkthdr));
    int copy_len = (int)hdr->len > PKT_BUF_SZ ? PKT_BUF_SZ : (int)hdr->len;
    memcpy(pkt->data, data, (size_t)copy_len);
    pkt->data_len = copy_len;
    ctx->batch_count++;
}

/*
 * capture_get_dropped — 获取 pcap 底层丢包统计
 *   dropped:    pcap_stats.ps_drop (内核丢包)
 *   if_dropped: pcap_stats.ps_ifdrop (接口丢包)
 *   return: 0 成功, -1 失败 (无 handle 或获取失败)
 */
int capture_get_dropped(unsigned long *dropped, unsigned long *if_dropped)
{
    if (!g_handle || !dropped || !if_dropped) return -1;
    struct pcap_stat ps;
    if (pcap_stats(g_handle, &ps) != 0) return -1;
    *dropped = (unsigned long)ps.ps_drop;
    *if_dropped = (unsigned long)ps.ps_ifdrop;
    return 0;
}

/* ──────────────────────────────────────────────
 *  UI ring buffer — 环形缓冲区实现
 * ────────────────────────────────────────────── */

/*
 * ui_ring_init — 初始化 UI 环形缓冲区
 *   r:        指向 ui_ring 结构体
 *   capacity: 缓冲区容量
 */
void ui_ring_init(ui_ring *r, int capacity)
{
    r->entries = (ui_ring_entry *)calloc((size_t)capacity, sizeof(ui_ring_entry));
    r->capacity = capacity;
    r->head = 0;
    r->tail = 0;
    r->count = 0;
    pthread_mutex_init(&r->mutex, NULL);
    LOG_INFO("ui_ring init OK, capacity=%d", capacity);
}

/*
 * ui_ring_destroy — 销毁 UI 环形缓冲区
 */
void ui_ring_destroy(ui_ring *r)
{
    if (r->entries) { free(r->entries); r->entries = NULL; }
    pthread_mutex_destroy(&r->mutex);
}

/*
 * ui_ring_push — 向环形缓冲区写入一个包 (满则丢弃)
 */
void ui_ring_push(ui_ring *r, const struct pcap_pkthdr *hdr, const u_char *data, int len)
{
    pthread_mutex_lock(&r->mutex);
    if (r->count >= r->capacity) {
        pthread_mutex_unlock(&r->mutex);
        return;
    }
    ui_ring_entry *e = &r->entries[r->tail];
    memcpy(&e->hdr, hdr, sizeof(struct pcap_pkthdr));
    e->data_len = len > PKT_BUF_SZ ? PKT_BUF_SZ : len;
    memcpy(e->data, data, (size_t)e->data_len);
    e->valid = 1;
    r->tail = (r->tail + 1) % r->capacity;
    r->count++;
    pthread_mutex_unlock(&r->mutex);
}

/*
 * ui_ring_pop — 从环形缓冲区读取一个包
 *   return: 1 成功, 0 缓冲区为空
 */
int ui_ring_pop(ui_ring *r, ui_ring_entry *e)
{
    pthread_mutex_lock(&r->mutex);
    if (r->count == 0) {
        pthread_mutex_unlock(&r->mutex);
        return 0;
    }
    memcpy(e, &r->entries[r->head], sizeof(ui_ring_entry));
    r->entries[r->head].valid = 0;
    r->head = (r->head + 1) % r->capacity;
    r->count--;
    pthread_mutex_unlock(&r->mutex);
    return 1;
}

/* ──────────────────────────────────────────────
 *  Packet queue — 多生产者/多消费者队列
 * ────────────────────────────────────────────── */

/*
 * pkt_queue_init — 初始化报文队列
 *   q:        指向队列结构体
 *   capacity: 队列容量
 */
void pkt_queue_init(pkt_queue *q, int capacity)
{
    q->entries = (pkt_entry *)calloc((size_t)capacity, sizeof(pkt_entry));
    if (!q->entries) {
        LOG_ERROR("pkt_queue_init calloc failed, capacity=%d size=%zu", capacity, sizeof(pkt_entry));
        return;
    }
    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->shutdown = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    LOG_INFO("pkt_queue init OK, capacity=%d entry=%zuB total=%zuMB",
             capacity, sizeof(pkt_entry),
             ((size_t)capacity * sizeof(pkt_entry)) / (1024 * 1024));
}

/*
 * pkt_queue_destroy — 销毁报文队列
 */
void pkt_queue_destroy(pkt_queue *q)
{
    if (q->entries) {
        free(q->entries);
        q->entries = NULL;
    }
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
    LOG_INFO("pkt_queue destroyed");
}

/*
 * pkt_queue_push — 向队列推送单个包 (阻塞，满则丢弃)
 */
int pkt_queue_push(pkt_queue *q, pkt_entry *pkt)
{
    pthread_mutex_lock(&q->mutex);
    if (q->shutdown) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    if (q->count >= q->capacity) {
        g_dropped++;
        if (g_dropped % 2000 == 1)
            LOG_WARN("pkt_queue full, dropped=%lu", g_dropped);
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    memcpy(&q->entries[q->tail], pkt, sizeof(pkt_entry));
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

/*
 * pkt_queue_push_batch — 批量推送 (trylock 非阻塞，避免阻塞抓包线程)
 *   return: 实际推送成功的数量
 */
int pkt_queue_push_batch(pkt_queue *q, pkt_entry *pkts, int count)
{
    if (count <= 0) return 0;

    /* try-lock: 如果解析器慢且持有锁，不阻塞抓包线程 — 直接丢弃 */
    if (pthread_mutex_trylock(&q->mutex) != 0) {
        g_dropped += (unsigned long)count;
        return 0;
    }

    if (q->shutdown) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    int pushed = 0;
    for (int i = 0; i < count; i++) {
        if (q->count >= q->capacity) {
            g_dropped += (unsigned long)(count - i);
            if (g_dropped % 2000 < (unsigned long)count)
                LOG_WARN("pkt_queue full, dropped=%lu", g_dropped);
            break;
        }
        memcpy(&q->entries[q->tail], &pkts[i], sizeof(pkt_entry));
        q->tail = (q->tail + 1) % q->capacity;
        q->count++;
        pushed++;
    }
    if (pushed > 0) {
        if (pushed > 1)
            pthread_cond_broadcast(&q->not_empty);
        else
            pthread_cond_signal(&q->not_empty);
    }
    pthread_mutex_unlock(&q->mutex);
    return pushed;
}

/*
 * pkt_queue_pop — 从队列取一个包 (阻塞等待)
 *   return: 1 成功, 0 队列已关闭且为空
 */
int pkt_queue_pop(pkt_queue *q, pkt_entry *pkt)
{
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !q->shutdown) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    if (q->shutdown && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    memcpy(pkt, &q->entries[q->head], sizeof(pkt_entry));
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

/*
 * pkt_queue_shutdown — 关闭队列，唤醒所有等待线程
 */
void pkt_queue_shutdown(pkt_queue *q)
{
    pthread_mutex_lock(&q->mutex);
    q->shutdown = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
}

/* ──────────────────────────────────────────────
 *  Thread functions
 * ────────────────────────────────────────────── */

/*
 * capture_loop — 抓包主循环
 *
 * 流程:
 *   1. pcap_dispatch 批量采集 → batch_buf
 *   2. 直接 pcap_dump 写入 pcap 文件 (无额外队列/拷贝)
 *   3. trylock 推送解析队列
 *   4. 推入 UI 环形缓冲区
 */
static void *capture_loop(void *arg)
{
    (void)arg;
    LOG_INFO("capture thread started, tid=%ld", (long)syscall(SYS_gettid));

    pkt_entry *batch_buf = (pkt_entry *)malloc((size_t)CAPTURE_BATCH * sizeof(pkt_entry));
    if (!batch_buf) {
        LOG_ERROR("capture batch buffer malloc failed");
        return NULL;
    }
    capture_batch_ctx ctx = { batch_buf, 0, CAPTURE_BATCH };

    while (!exit_flag && g_capture_running) {
        ctx.batch_count = 0;
        int n = pcap_dispatch(g_handle, CAPTURE_BATCH, pkt_callback, (u_char *)&ctx);

        if (n > 0) {
            /* 1) DUMP: 直接写 pcap 文件 (内联, 无额外队列) */
            if (g_dumper) {
                for (int i = 0; i < ctx.batch_count; i++) {
                    pcap_dump((u_char *)g_dumper, &batch_buf[i].hdr, batch_buf[i].data);
                }
            }

            /* 2) PARSER PATH: trylock 非阻塞推送 */
            pkt_queue_push_batch(&g_pkt_queue, batch_buf, ctx.batch_count);

            if (use_ui && !capture_pause) {
                for (int i = 0; i < ctx.batch_count; i++) {
                    ui_ring_push(&g_ui_ring, &batch_buf[i].hdr, batch_buf[i].data, batch_buf[i].data_len);
                }
            }
        } else if (n == 0 && g_is_offline) {
            /* offline file EOF */
            LOG_INFO("pcap_dispatch: EOF from offline file (0 packets)");
            exit_flag = 1;
            break;
        } else if (n == -1) {
            LOG_ERROR("pcap_dispatch error: %s", pcap_geterr(g_handle));
            break;
        }
        /* n == 0 for live capture: timeout (normal), continue */
    }

    free(batch_buf);

    LOG_INFO("capture thread exiting, total pkt_queue dropped=%lu",
             g_dropped);
    pkt_queue_shutdown(&g_pkt_queue);
    return NULL;
}

/*
 * parser_worker — 解析线程工作函数
 *   从队列取包 → parse_packet 解析
 */
static void *parser_worker(void *arg)
{
    pkt_queue *q = (pkt_queue *)arg;
    LOG_INFO("parser worker started, tid=%ld", (long)syscall(SYS_gettid));

    pkt_entry pkt;
    while (pkt_queue_pop(q, &pkt)) {
        parse_packet(&pkt.hdr, pkt.data);
    }

    LOG_INFO("parser worker exiting, tid=%ld", (long)syscall(SYS_gettid));
    return NULL;
}

/* ──────────────────────────────────────────────
 *  Thread start / stop API
 * ────────────────────────────────────────────── */

/*
 * capture_thread_start — 启动抓包线程
 *   return: 0 成功, -1 失败
 */
int capture_thread_start(void)
{
    g_capture_running = 1;
    if (use_ui) ui_ring_init(&g_ui_ring, UI_RING_SIZE);
    int ret = pthread_create(&g_capture_tid, NULL, capture_loop, NULL);
    if (ret != 0) {
        LOG_ERROR("pthread_create capture_loop failed: %s", strerror(ret));
        g_capture_running = 0;
        return -1;
    }
    LOG_INFO("capture thread launched OK");
    return 0;
}

/*
 * capture_thread_stop — 停止抓包线程
 *
 * 修复了时序竞态: g_capture_running = 0 之后使用内存屏障，
 * 确保 pcap_breakloop 看到最新的 g_capture_running 值，
 * 避免退出卡死。
 */
void capture_thread_stop(void)
{
    LOG_INFO("stopping capture thread...");
    g_capture_running = 0;
    __sync_synchronize();  /* memory barrier: 确保写对 pcap_breakloop 可见 */
    if (g_handle) pcap_breakloop(g_handle);
    pkt_queue_shutdown(&g_pkt_queue);
    pthread_join(g_capture_tid, NULL);
    if (use_ui) ui_ring_destroy(&g_ui_ring);
    LOG_INFO("capture thread joined");
}

/*
 * parser_workers_start — 启动 N 个解析器工作线程
 *   n: 工作线程数 (最多 PARSER_WORKERS)
 *   q: 共享报文队列
 *   return: 0 成功, -1 失败
 */
int parser_workers_start(int n, pkt_queue *q)
{
    if (n > PARSER_WORKERS) n = PARSER_WORKERS;
    g_parsers_running = 1;
    for (int i = 0; i < n; i++) {
        int ret = pthread_create(&g_parser_tids[i], NULL, parser_worker, (void *)q);
        if (ret != 0) {
            LOG_ERROR("pthread_create parser_worker[%d] failed: %s", i, strerror(ret));
            return -1;
        }
    }
    LOG_INFO("parser workers started, count=%d", n);
    return 0;
}

/*
 * parser_workers_stop — 停止所有解析器工作线程
 */
void parser_workers_stop(void)
{
    LOG_INFO("stopping parser workers...");
    g_parsers_running = 0;
    for (int i = 0; i < PARSER_WORKERS; i++) {
        pthread_join(g_parser_tids[i], NULL);
    }
    LOG_INFO("parser workers all joined");
}

/* ──────────────────────────────────────────────
 *  libpcap open / close
 * ────────────────────────────────────────────── */

/*
 * open_capture — 打开实时网卡抓包
 *   dev:    网卡名称
 *   filter: BPF 过滤表达式 (可为 NULL)
 *   return: 0 成功, -1 失败
 */
int open_capture(const char *dev, const char *filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(dev, 65535, 1, PCAP_TIMEOUT_MS, errbuf);
    if (!g_handle) {
        LOG_ERROR("pcap_open_live failed: %s", errbuf);
        return -1;
    }

    if (pcap_set_immediate_mode(g_handle, 1) != 0) {
        LOG_WARN("pcap_set_immediate_mode not supported on this platform");
    } else {
        LOG_INFO("pcap_set_immediate_mode enabled");
    }

    int r = pcap_set_buffer_size(g_handle, PCAP_BUF_MB * 1024 * 1024);
    if (r != 0) {
        LOG_WARN("pcap_set_buffer_size failed: %s", pcap_geterr(g_handle));
    } else {
        LOG_INFO("pcap_set_buffer_size OK, user_buf=%dMB", PCAP_BUF_MB);
    }

    int sockfd = pcap_get_selectable_fd(g_handle);
    if (sockfd >= 0) {
        int rcvbuf = KERNEL_BUF_MB * 1024 * 1024;
        socklen_t optlen = sizeof(rcvbuf);
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == 0) {
            int actual = 0;
            if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &actual, &optlen) == 0) {
                LOG_INFO("kernel SO_RCVBUF set, requested=%dMB actual=%dMB",
                         KERNEL_BUF_MB, actual / (1024 * 1024));
            }
        } else {
            LOG_WARN("setsockopt SO_RCVBUF failed: %s", strerror(errno));
        }
    }

    LOG_INFO("pcap_open_live OK, dev=%s", dev);

    if (filter && strlen(filter) > 0) {
        struct bpf_program fp;
        bpf_u_int32 netmask, ip;
        if (pcap_lookupnet(dev, &ip, &netmask, errbuf) == 0) {
            if (pcap_compile(g_handle, &fp, filter, 0, netmask) < 0 ||
                pcap_setfilter(g_handle, &fp) < 0) {
                LOG_ERROR("BPF filter compile/set failed: %s", pcap_geterr(g_handle));
                return -1;
            }
            LOG_INFO("BPF filter loaded: %s", filter);
        }
    }
    return 0;
}

/*
 * open_pcap_file — 打开离线 pcap 文件回放
 *   path: pcap 文件路径
 *   return: 0 成功, -1 失败
 */
int open_pcap_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_offline(path, errbuf);
    if (!g_handle) {
        LOG_ERROR("pcap_open_offline failed: %s", errbuf);
        return -1;
    }
    g_is_offline = 1;
    LOG_INFO("pcap_open_offline OK, path=%s", path);
    return 0;
}

/*
 * save_pcap — 打开 pcap dump 文件
 *   path: 输出文件路径
 *   return: 0 成功, -1 失败
 */
int save_pcap(const char *path)
{
    if (!g_handle) return -1;
    g_dumper = pcap_dump_open(g_handle, path);
    if (g_dumper) {
        LOG_INFO("pcap_dump_open OK, path=%s", path);
        return 0;
    }
    LOG_ERROR("pcap_dump_open failed, path=%s", path);
    return -1;
}

/*
 * close_capture — 关闭抓包句柄
 */
void close_capture(void)
{
    if (g_dumper) { 
        pcap_dump_flush(g_dumper);
        pcap_dump_close(g_dumper); 
        g_dumper = NULL; 
    }
    if (g_handle) { pcap_close(g_handle); g_handle = NULL; }
    LOG_INFO("capture closed");
}
