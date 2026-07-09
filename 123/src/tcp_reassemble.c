/*
 * tcp_reassemble.c — TCP 流重组模块
 *
 * 功能:
 *   1. 基于 TCP 序列号拼接载荷, 提取完整 HTTP 请求/响应
 *   2. 支持 OOO (乱序) 数据段缓存与合并 (最多 4 个待合并段)
 *   3. 动态可扩容缓冲区: 初始 8KB, 上限 2MB, 避免大 HTTP 报文解析失败
 *   4. 分桶锁 (256 个 per-bucket mutex) 实现高并发访问
 *   5. 空闲流回收 (60s 无活动)
 *
 * 设计:
 *   - tcp_flow 串联在哈希表 collision chain 上
 *   - 每个 bucket 独立加锁
 *   - 缓冲区使用 realloc 动态扩容
 */

#include "common.h"
#include "traffic_stat.h"
#include "http_parser.h"
#include <errno.h>

#define FLOW_HASH_BUCKETS 256
#define MAX_OUT_OF_ORDER  4

/* per-bucket mutexes — 替换全局单一锁, 大幅降低竞争 */
static pthread_mutex_t flow_mutex[FLOW_HASH_BUCKETS];

/* ── 待合并 (乱序) 数据段 ── */
typedef struct {
    u_uint seq;       /* TCP 序列号 */
    int    len;        /* 数据长度 */
    char  *data;       /* 动态分配的数据缓冲区 */
    int    data_cap;   /* 缓冲区容量 */
} tcp_pending_seg;

/* ── TCP 流结构体 ── */
typedef struct tcp_flow_s {
    tcp_flow_key key;
    u_uint exp_seq;           /* 期望下一个字节的序列号 */
    char  *buf;               /* 动态分配的拼接缓冲区 */
    int    buf_len;           /* 缓冲区当前有效数据长度 */
    int    buf_cap;           /* 缓冲区总容量 */
    int    seq_initialized;   /* 是否已从第一个包初始化 exp_seq */
    time_t last_active;       /* 最后活跃时间 */
    tcp_pending_seg pending[MAX_OUT_OF_ORDER];  /* OOO 缓存 */
    int    pending_cnt;
    struct tcp_flow_s *next;  /* 哈希冲突链表 */
} tcp_flow;

static tcp_flow *tcp_flow_hash[FLOW_HASH_BUCKETS] = {NULL};
static int flow_cnt = 0;

/* freelist for tcp_flow nodes */
static tcp_flow *flow_freelist = NULL;
static pthread_mutex_t freelist_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── HTTP 配对日志 ── */
static FILE *g_http_pair_fp = NULL;
static pthread_mutex_t g_pair_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── 前一个消息缓存 (用于请求-响应配对) ── */
typedef struct {
    char *data;
    int   len;
    int   is_request;   /* 1 = request, 0 = response */
} http_pair_cache;

static http_pair_cache g_last_msg = { NULL, 0, -1 };

/* ──────────────────────────────────────────────
 *  内部辅助: 缓冲区扩容
 * ────────────────────────────────────────────── */

/*
 * buf_ensure_capacity — 确保缓冲区至少有 need 字节可用空间
 *
 * 策略: 初始 FLOW_BUF_INIT (8KB), 翻倍扩容, 上限 FLOW_BUF_MAX (2MB)。
 *       超过上限则截断: 清空缓冲区并从头开始。
 *
 *   pbuf: 指向缓冲区指针的指针
 *   pcap: 指向当前容量的指针
 *   need: 需要的最小容量
 *   max:  容量上限
 *   return: 1 成功, 0 截断
 */
static int buf_ensure_capacity(char **pbuf, int *pcap, int need, int max)
{
    if (*pcap >= need) return 1;

    int new_cap = *pcap > 0 ? *pcap : FLOW_BUF_INIT;
    while (new_cap < need) {
        if (new_cap > max / 2) {
            new_cap = max;
            break;
        }
        new_cap *= 2;
    }
    if (new_cap > max) new_cap = max;

    if (new_cap <= *pcap) {
        /* 已达上限, 截断 */
        return 0;
    }

    char *new_buf = (char *)realloc(*pbuf, (size_t)new_cap);
    if (!new_buf) {
        LOG_ERROR("buf_ensure_capacity: realloc failed, cap=%d", new_cap);
        return 0;
    }
    /* 清零新分配区域 */
    memset(new_buf + *pcap, 0, (size_t)(new_cap - *pcap));
    *pbuf = new_buf;
    *pcap = new_cap;
    return 1;
}

/* ──────────────────────────────────────────────
 *  流哈希函数 (支持 IPv4/IPv6)
 * ────────────────────────────────────────────── */

/*
 * flow_key_hash — 计算 tcp_flow_key 的哈希桶索引
 *
 * IPv4: 使用 sip ^ dip ^ sp ^ dp
 * IPv6: 额外 XOR 128 位地址的 4 个 32-bit 字
 */
static unsigned int flow_key_hash(const tcp_flow_key *k)
{
    unsigned int h = k->sip ^ (k->dip << 13) ^ (k->sp << 8) ^ k->dp;
    if (k->is_ipv6) {
        /* XOR IPv6 地址的额外 96 位 */
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
    return h % FLOW_HASH_BUCKETS;
}

/*
 * flow_key_equal — 比较两个 tcp_flow_key 是否相等
 */
static int flow_key_equal(const tcp_flow_key *a, const tcp_flow_key *b)
{
    if (a->is_ipv6 != b->is_ipv6) return 0;
    if (a->sp != b->sp || a->dp != b->dp) return 0;
    if (a->is_ipv6) {
        return (memcmp(a->sip6, b->sip6, IPV6_LEN) == 0 &&
                memcmp(a->dip6, b->dip6, IPV6_LEN) == 0);
    }
    return (a->sip == b->sip && a->dip == b->dip);
}

/* ──────────────────────────────────────────────
 *  流节点分配与回收
 * ────────────────────────────────────────────── */

/*
 * flow_alloc — 分配一个 tcp_flow 节点 (优先从 freelist)
 */
static tcp_flow *flow_alloc(void)
{
    pthread_mutex_lock(&freelist_mutex);
    if (flow_freelist) {
        tcp_flow *f = flow_freelist;
        flow_freelist = f->next;
        pthread_mutex_unlock(&freelist_mutex);
        memset(f, 0, sizeof(tcp_flow));
        return f;
    }
    pthread_mutex_unlock(&freelist_mutex);
    tcp_flow *f = (tcp_flow *)calloc(1, sizeof(tcp_flow));
    return f;
}

/*
 * flow_free — 释放一个 tcp_flow 节点至 freelist
 */
static void flow_free(tcp_flow *f)
{
    if (!f) return;
    /* 释放动态分配的缓冲区 */
    free(f->buf);
    f->buf = NULL;
    f->buf_cap = 0;
    f->buf_len = 0;
    /* 释放 pending segment 缓冲区 */
    for (int i = 0; i < MAX_OUT_OF_ORDER; i++) {
        free(f->pending[i].data);
        f->pending[i].data = NULL;
        f->pending[i].data_cap = 0;
        f->pending[i].len = 0;
    }
    f->pending_cnt = 0;
    /* 加入 freelist */
    pthread_mutex_lock(&freelist_mutex);
    f->next = flow_freelist;
    flow_freelist = f;
    pthread_mutex_unlock(&freelist_mutex);
}

/*
 * find_or_create_flow_locked — 查找或创建 TCP 流 (调用者持有 bucket 锁)
 *
 * 策略: 先查找匹配的流, 未找到则复用超时流或分配新流。
 *   bucket: 哈希桶索引
 *   k:      五元组键值
 *   now:    当前时间
 *   return: 找到或创建的流指针, NULL 表示分配失败
 */
static tcp_flow *find_or_create_flow_locked(unsigned int bucket,
                                             const tcp_flow_key *k, time_t now)
{
    tcp_flow *prev = NULL;
    tcp_flow *f = tcp_flow_hash[bucket];
    tcp_flow *idle = NULL, *idle_prev = NULL;

    while (f) {
        if (flow_key_equal(&f->key, k)) {
            return f;  /* found */
        }
        if (!idle && (now - f->last_active) > 30) {
            idle = f;
            idle_prev = prev;
        }
        prev = f;
        f = f->next;
    }

    /* not found — reuse idle or allocate new */
    tcp_flow *nf;
    if (idle) {
        nf = idle;
        if (idle_prev)
            idle_prev->next = idle->next;
        else
            tcp_flow_hash[bucket] = idle->next;
        /* free old buffers before reuse */
        free(nf->buf);
        for (int i = 0; i < MAX_OUT_OF_ORDER; i++) free(nf->pending[i].data);
    } else {
        nf = flow_alloc();
        if (!nf) return NULL;
        flow_cnt++;
    }

    memset(nf, 0, sizeof(tcp_flow));
    nf->key = *k;
    nf->exp_seq = 0;
    nf->last_active = now;
    nf->next = tcp_flow_hash[bucket];
    tcp_flow_hash[bucket] = nf;
    return nf;
}

/* ──────────────────────────────────────────────
 *  HTTP 配对日志
 * ────────────────────────────────────────────── */

/*
 * http_pair_log_init — 初始化 HTTP 配对日志文件
 */
void http_pair_log_init(void)
{
    pthread_mutex_lock(&g_pair_mutex);
    if (!g_http_pair_fp) {
        g_http_pair_fp = fopen("http_pairs.log", "a");
        if (g_http_pair_fp) {
            time_t now = time(NULL);
            fprintf(g_http_pair_fp, "\n===== HTTP Pairs Session: %s", ctime(&now));
            fflush(g_http_pair_fp);
        }
    }
    pthread_mutex_unlock(&g_pair_mutex);
}

/*
 * http_pair_log_close — 关闭 HTTP 配对日志文件
 */
void http_pair_log_close(void)
{
    pthread_mutex_lock(&g_pair_mutex);
    if (g_http_pair_fp) {
        fprintf(g_http_pair_fp, "===== End of session =====\n");
        fflush(g_http_pair_fp);
        fclose(g_http_pair_fp);
        g_http_pair_fp = NULL;
    }
    free(g_last_msg.data);
    g_last_msg.data = NULL;
    g_last_msg.len = 0;
    g_last_msg.is_request = -1;
    pthread_mutex_unlock(&g_pair_mutex);
}

/*
 * http_pair_log_write — 写入请求-响应对到 http_pairs.log
 *
 * 策略: 缓存上一个消息。如果是请求后跟响应, 则作为一对写入。
 *       否则单独写入 (请求或响应不匹配的情况)。
 */
static void http_pair_log_write(const http_message_t *msg)
{
    if (!msg) return;

    pthread_mutex_lock(&g_pair_mutex);
    if (!g_http_pair_fp) {
        g_http_pair_fp = fopen("http_pairs.log", "a");
    }
    if (!g_http_pair_fp) {
        pthread_mutex_unlock(&g_pair_mutex);
        return;
    }

    int is_req = (msg->type == HTTP_REQUEST);

    if (g_last_msg.is_request == 1 && !is_req) {
        /* ── 请求→响应配对 ── */
        fprintf(g_http_pair_fp, "[PAIR] ==============================================\n");
        fprintf(g_http_pair_fp, "[REQUEST]  %s\n",
                g_last_msg.data ? g_last_msg.data : "(unknown)");
        fprintf(g_http_pair_fp, "[RESPONSE] %.*s %d %.*s (body=%d)\n",
                msg->version_len, msg->version ? msg->version : "HTTP/1.1",
                msg->status_code,
                msg->status_phrase_len, msg->status_phrase ? msg->status_phrase : "",
                msg->body_len);
        fprintf(g_http_pair_fp, "======================================================\n");
        fflush(g_http_pair_fp);

        free(g_last_msg.data);
        g_last_msg.data = NULL;
        g_last_msg.len = 0;
        g_last_msg.is_request = -1;
    } else {
        /* ── 上一个未配对的消息, 先单独输出 ── */
        if (g_last_msg.data && g_last_msg.len > 0) {
            fprintf(g_http_pair_fp, "[UNPAIRED-%s]\n",
                    g_last_msg.is_request ? "REQ" : "RESP");
            fwrite(g_last_msg.data, 1, (size_t)g_last_msg.len, g_http_pair_fp);
            fprintf(g_http_pair_fp, "\n");
        }

        /* 缓存当前消息 */
        free(g_last_msg.data);
        g_last_msg.data = NULL;

        /* 序列化当前消息的摘要 */
        char summary[512];
        if (is_req) {
            snprintf(summary, sizeof(summary),
                     "%.*s %.*s %.*s",
                     msg->method_len, msg->method_str ? msg->method_str : "?",
                     msg->uri_len, msg->uri ? msg->uri : "/",
                     msg->version_len, msg->version ? msg->version : "");
        } else {
            snprintf(summary, sizeof(summary),
                     "%.*s %d %.*s",
                     msg->version_len, msg->version ? msg->version : "HTTP/1.1",
                     msg->status_code,
                     msg->status_phrase_len, msg->status_phrase ? msg->status_phrase : "");
        }
        int slen = (int)strlen(summary);
        g_last_msg.data = (char *)malloc((size_t)(slen + 1));
        if (g_last_msg.data) {
            memcpy(g_last_msg.data, summary, (size_t)(slen + 1));
            g_last_msg.len = slen;
        }
        g_last_msg.is_request = is_req ? 1 : 0;
    }

    pthread_mutex_unlock(&g_pair_mutex);
}

/* ──────────────────────────────────────────────
 *  HTTP 消息输出
 * ────────────────────────────────────────────── */

/*
 * output_http_message — 输出完整 HTTP 消息
 *
 *   解析 → 统计 → 日志 → 打印 → 配对日志写入
 *   msg_buf: 原始 HTTP 消息缓冲区
 *   msg_len: 消息长度
 */
static void output_http_message(const char *msg_buf, int msg_len)
{
    if (msg_len <= 0) return;

    http_message_t *msg = http_message_parse((const u_char *)msg_buf, msg_len);
    if (!msg) return;

    stat_inc_http_reassemble();

    /* structured one-line debug log */
    http_message_log(msg);

    /* full human-readable dump to stdout */
    http_message_print(msg);

    /* write to http_pairs.log */
    http_pair_log_write(msg);

    http_message_free(msg);
}

/* ──────────────────────────────────────────────
 *  OOO 乱序段合并
 * ────────────────────────────────────────────── */

/*
 * try_merge_pending — 尝试合并缓存的 OOO 数据段
 *
 * 遍历 pending 数组, 找到序列号恰好接续的数据段并合并到主缓冲区。
 * 循环直到没有更多可合并的段。
 */
static void try_merge_pending(tcp_flow *f)
{
    int merged = 1;
    while (merged) {
        merged = 0;
        for (int i = 0; i < f->pending_cnt; i++) {
            if (f->pending[i].seq == f->exp_seq + (u_uint)f->buf_len) {
                int need = f->buf_len + f->pending[i].len;
                if (!buf_ensure_capacity(&f->buf, &f->buf_cap, need, FLOW_BUF_MAX)) {
                    /* 截断: 清空缓冲区 */
                    f->buf_len = 0;
                    f->pending_cnt = 0;
                    f->exp_seq = f->pending[i].seq;
                }
                int room = f->buf_cap - f->buf_len;
                int copy_len = f->pending[i].len < room ? f->pending[i].len : room;
                memcpy(f->buf + f->buf_len, f->pending[i].data, (size_t)copy_len);
                f->buf_len += copy_len;
                f->exp_seq += (u_uint)copy_len;

                /* 释放被合并的 pending segment */
                free(f->pending[i].data);
                f->pending[i].data = NULL;
                f->pending[i].data_cap = 0;

                int tail_count = f->pending_cnt - i - 1;
                if (tail_count > 0) {
                    memmove(&f->pending[i], &f->pending[i + 1],
                            (size_t)tail_count * sizeof(tcp_pending_seg));
                }
                f->pending_cnt--;
                merged = 1;
                break;
            }
        }
    }
}

/* ──────────────────────────────────────────────
 *  HTTP 消息边界提取
 * ────────────────────────────────────────────── */

/*
 * extract_http_message — 从流缓冲区中提取一条完整 HTTP 消息
 *
 * 支持三种边界检测模式:
 *   1. Content-Length: 固定长度 body
 *   2. Transfer-Encoding: chunked → 扫描零长度块标记结束
 *   3. Connection: close → 所有可用数据作为一条消息
 *
 *   f:       TCP 流
 *   out_buf: 输出缓冲区 (调用者提供, 上限 FLOW_BUF_MAX)
 *   out_len: 输出消息长度
 *   return: 1 成功提取, 0 数据不完整
 */
static int extract_http_message(tcp_flow *f, char *out_buf, int *out_len)
{
    *out_len = 0;

    /* 1. 查找 header 终止符 \r\n\r\n */
    char *sep = strstr(f->buf, "\r\n\r\n");
    if (!sep) return 0;

    int header_end = (int)(sep - f->buf) + 4;
    int header_len = header_end;
    int content_len = 0;
    int is_chunked  = 0;
    int conn_close  = 0;

    /* 2. 检测 body 边界提示 */
    http_detect_content_length(f->buf, header_len, &content_len);
    is_chunked = http_detect_chunked(f->buf, header_len);
    conn_close = http_detect_connection_close(f->buf, header_len);

    int msg_len = 0;

    if (content_len > 0) {
        /* ── 固定长度 body ── */
        msg_len = header_end + content_len;
        if (f->buf_len < msg_len) return 0;
    } else if (is_chunked) {
        /* ── chunked 传输编码 ── */
        int decoded_len = 0, raw_len = 0;
        int complete = http_chunked_body_complete(
            (const u_char *)(f->buf + header_end),
            f->buf_len - header_end,
            &decoded_len, &raw_len);
        if (complete != 1) return 0;
        msg_len = header_end + raw_len;
        if (msg_len > FLOW_BUF_MAX) msg_len = FLOW_BUF_MAX;
    } else if (conn_close) {
        /* ── Connection: close — 全部可用数据 ── */
        msg_len = f->buf_len;
    } else {
        /* ── 无 body (或 Content-Length: 0) ── */
        msg_len = header_end;
    }

    if (msg_len <= 0 || msg_len > FLOW_BUF_MAX) return 0;
    if (f->buf_len < msg_len) return 0;

    memcpy(out_buf, f->buf, (size_t)msg_len);
    *out_len = msg_len;

    /* 滑动剩余数据 */
    int remain = f->buf_len - msg_len;
    if (remain > 0) {
        memmove(f->buf, f->buf + msg_len, (size_t)remain);
        f->buf_len = remain;
    } else {
        f->buf_len = 0;
    }

    return 1;
}

/* ──────────────────────────────────────────────
 *  Public API
 * ────────────────────────────────────────────── */

/*
 * tcp_flow_add — 向 TCP 流添加数据段 (公开接口)
 *
 * 流程:
 *   1. 查找或创建流 (分桶加锁)
 *   2. 序列号校验 (去重/重叠裁剪)
 *   3. 顺序数据: 拼接到主缓冲区, 触发 OOO 合并
 *   4. 乱序数据: 缓存到 pending 数组
 *   5. 尝试提取完整 HTTP 消息
 */
void tcp_flow_add(u_int sip, u_int dip,
                  const u_char *sip6, const u_char *dip6,
                  u_short sp, u_short dp,
                  u_uint seq, const u_char *pay, int len)
{
    /* 构建五元组键值 */
    tcp_flow_key k;
    memset(&k, 0, sizeof(k));
    k.sp = sp;
    k.dp = dp;

    if (sip6 && dip6) {
        k.is_ipv6 = 1;
        memcpy(k.sip6, sip6, IPV6_LEN);
        memcpy(k.dip6, dip6, IPV6_LEN);
        k.sip = sip;  /* 哈希值, 由调用者计算 */
        k.dip = dip;
    } else {
        k.is_ipv6 = 0;
        k.sip = sip;
        k.dip = dip;
    }

    time_t now = time(NULL);
    unsigned int bucket = flow_key_hash(&k);

    pthread_mutex_lock(&flow_mutex[bucket]);

    tcp_flow *f = find_or_create_flow_locked(bucket, &k, now);
    if (!f) {
        pthread_mutex_unlock(&flow_mutex[bucket]);
        return;
    }

    f->last_active = now;

    /* 第一个包初始化期望序列号 */
    if (!f->seq_initialized) {
        f->exp_seq = seq;
        f->seq_initialized = 1;
    }

    u_uint pkt_end_seq = seq + (u_uint)len;
    if (pkt_end_seq <= f->exp_seq) {
        pthread_mutex_unlock(&flow_mutex[bucket]);
        return;  /* 重复或已确认 */
    }

    u_uint overlap = 0;
    if (seq < f->exp_seq && pkt_end_seq > f->exp_seq)
        overlap = f->exp_seq - seq;

    const u_char *eff_pay = pay + overlap;
    int eff_len = len - (int)overlap;
    u_uint eff_seq = seq + overlap;

    if (eff_len <= 0) {
        pthread_mutex_unlock(&flow_mutex[bucket]);
        return;
    }

    if (eff_seq == f->exp_seq + (u_uint)f->buf_len) {
        /* ── 按序到达 ── */
        int need = f->buf_len + eff_len;
        if (!buf_ensure_capacity(&f->buf, &f->buf_cap, need, FLOW_BUF_MAX)) {
            /* 缓冲区溢满, 截断重置 */
            f->buf_len = 0;
            f->pending_cnt = 0;
            f->exp_seq = eff_seq;
            need = eff_len;
            buf_ensure_capacity(&f->buf, &f->buf_cap, need, FLOW_BUF_MAX);
        }
        int copy_len = eff_len;
        if (f->buf_len + copy_len > f->buf_cap)
            copy_len = f->buf_cap - f->buf_len;
        if (copy_len <= 0) {
            pthread_mutex_unlock(&flow_mutex[bucket]);
            return;
        }
        memcpy(f->buf + f->buf_len, eff_pay, (size_t)copy_len);
        f->buf_len += copy_len;
        f->exp_seq += (u_uint)copy_len;

        try_merge_pending(f);

        /* 尝试提取 HTTP 消息 */
        /* 使用动态缓冲区 (上限 2MB) */
        char *http_buf = (char *)malloc((size_t)FLOW_BUF_MAX);
        if (http_buf) {
            int http_len = 0;
            while (extract_http_message(f, http_buf, &http_len)) {
                /* 解锁后输出, 避免锁内做 I/O */
                pthread_mutex_unlock(&flow_mutex[bucket]);
                output_http_message(http_buf, http_len);
                pthread_mutex_lock(&flow_mutex[bucket]);
            }
            free(http_buf);
        }

        pthread_mutex_unlock(&flow_mutex[bucket]);
    } else if (eff_seq > f->exp_seq + (u_uint)f->buf_len) {
        /* ── 乱序到达: 缓存到 pending ── */
        if (f->pending_cnt < MAX_OUT_OF_ORDER && eff_len > 0) {
            tcp_pending_seg *ps = &f->pending[f->pending_cnt];
            /* 为 pending segment 分配/扩容缓冲区 */
            if (!ps->data || ps->data_cap < eff_len) {
                free(ps->data);
                int seg_cap = eff_len > FLOW_BUF_INIT ? eff_len : FLOW_BUF_INIT;
                if (seg_cap > FLOW_BUF_MAX) seg_cap = FLOW_BUF_MAX;
                ps->data = (char *)malloc((size_t)seg_cap);
                ps->data_cap = seg_cap;
            }
            if (ps->data) {
                ps->seq = eff_seq;
                ps->len = eff_len < ps->data_cap ? eff_len : ps->data_cap;
                memcpy(ps->data, eff_pay, (size_t)ps->len);
                f->pending_cnt++;
            }
        }
        pthread_mutex_unlock(&flow_mutex[bucket]);
    } else {
        /* ── 重叠: 已处理 ── */
        pthread_mutex_unlock(&flow_mutex[bucket]);
    }
}

/*
 * tcp_flow_clear_all — 清空所有 TCP 流
 */
void tcp_flow_clear_all(void)
{
    for (int i = 0; i < FLOW_HASH_BUCKETS; i++) {
        pthread_mutex_lock(&flow_mutex[i]);
    }
    for (int i = 0; i < FLOW_HASH_BUCKETS; i++) {
        tcp_flow *f = tcp_flow_hash[i];
        while (f) {
            tcp_flow *next = f->next;
            flow_free(f);
            f = next;
        }
        tcp_flow_hash[i] = NULL;
    }
    flow_cnt = 0;
    for (int i = 0; i < FLOW_HASH_BUCKETS; i++) {
        pthread_mutex_unlock(&flow_mutex[i]);
    }
}

/*
 * tcp_flow_active_count — 返回活跃流数量 (30s 内有活动)
 */
int tcp_flow_active_count(void)
{
    int cnt = 0;
    time_t now = time(NULL);
    for (int i = 0; i < FLOW_HASH_BUCKETS; i++) {
        pthread_mutex_lock(&flow_mutex[i]);
        tcp_flow *f = tcp_flow_hash[i];
        while (f) {
            if ((now - f->last_active) <= 30) cnt++;
            f = f->next;
        }
        pthread_mutex_unlock(&flow_mutex[i]);
    }
    return cnt;
}

/*
 * tcp_flow_reap — 回收超时流 (60s 无活动)
 */
void tcp_flow_reap(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < FLOW_HASH_BUCKETS; i++) {
        pthread_mutex_lock(&flow_mutex[i]);
        tcp_flow *prev = NULL;
        tcp_flow *f = tcp_flow_hash[i];
        int reaped = 0;
        while (f) {
            tcp_flow *next = f->next;
            if ((now - f->last_active) > 60) {
                if (prev)
                    prev->next = next;
                else
                    tcp_flow_hash[i] = next;
                flow_free(f);
                flow_cnt--;
                reaped++;
            } else {
                prev = f;
            }
            f = next;
        }
        if (reaped > 0) {
            LOG_DEBUG("tcp_flow_reap bucket[%d]: removed %d expired flows", i, reaped);
        }
        pthread_mutex_unlock(&flow_mutex[i]);
    }
}

/*
 * tcp_flow_stats — 获取流统计快照 (供 UI 展示)
 */
void tcp_flow_stats(char *buf, size_t len)
{
    if (!buf || len == 0) return;
    int total_flows = 0, active_flows = 0;
    int total_buf_bytes = 0;
    time_t now = time(NULL);

    for (int i = 0; i < FLOW_HASH_BUCKETS; i++) {
        pthread_mutex_lock(&flow_mutex[i]);
        tcp_flow *f = tcp_flow_hash[i];
        while (f) {
            total_flows++;
            if ((now - f->last_active) <= 30) {
                active_flows++;
                total_buf_bytes += f->buf_len;
            }
            f = f->next;
        }
        pthread_mutex_unlock(&flow_mutex[i]);
    }

    snprintf(buf, len,
             "TCP Flows: %d total, %d active | Buffer: %d KB",
             total_flows, active_flows, total_buf_bytes / 1024);
}
