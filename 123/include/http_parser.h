#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H
#include "common.h"

/*
 * http_parser.h — HTTP/1.x 协议解析器
 *
 * 功能:
 *   - 完整解析 HTTP 请求行/状态行
 *   - 头部键值对提取 (零拷贝, 指向原始缓冲区)
 *   - 分块传输编码 (chunked) 自动解码
 *   - Content-Length / Connection: close 边界检测
 */

/* ── HTTP 方法枚举 ── */
typedef enum {
    HTTP_GET      = 0,
    HTTP_POST     = 1,
    HTTP_PUT      = 2,
    HTTP_DELETE   = 3,
    HTTP_HEAD     = 4,
    HTTP_PATCH    = 5,
    HTTP_OPTIONS  = 6,
    HTTP_CONNECT  = 7,
    HTTP_TRACE    = 8,
    HTTP_UNKNOWN  = 9
} http_method_t;

/* ── 消息类型 ── */
typedef enum {
    HTTP_REQUEST   = 0,
    HTTP_RESPONSE  = 1
} http_msg_type_t;

/* ── 单个头部键值对 (零拷贝: 指针指向原始缓冲区) ── */
typedef struct {
    char *name;
    int   name_len;
    char *value;
    int   value_len;
} http_header_t;

/* ── 完整解析的 HTTP 消息 ── */
typedef struct {
    http_msg_type_t type;

    /* --- request-line --- */
    http_method_t method;
    char *method_str;     /* 原始方法字符串, NULL for response */
    int   method_len;
    char *uri;
    int   uri_len;
    char *version;        /* "HTTP/1.0" or "HTTP/1.1", shared by req & resp */
    int   version_len;

    /* --- response-line --- */
    int   status_code;    /* 0 for request */
    char *status_phrase;  /* NULL for request */
    int   status_phrase_len;

    /* --- headers (动态数组) --- */
    http_header_t *headers;
    int header_count;
    int header_capacity;

    /* --- body (解码后, 分块已去除) --- */
    u_char *body;
    int body_len;
    int body_capacity;

    /* --- 从头部提取的元数据 --- */
    int is_chunked;
    int connection_close;
    int content_length;    /* -1 if not present */
} http_message_t;

/* ── Public API ── */

/*
 * http_method_from_str — 字符串转 HTTP 方法枚举
 *   s:   方法字符串
 *   len: 字符串长度
 *   return: 方法枚举值
 */
http_method_t http_method_from_str(const char *s, int len);

/*
 * http_method_name — 方法枚举转字符串
 *   m: 方法枚举值
 *   return: 方法名称字符串
 */
const char *http_method_name(http_method_t m);

/*
 * http_message_parse — 解析完整 HTTP 消息
 *   data: 原始消息缓冲区
 *   len:  缓冲区长度
 *   return: 堆分配的 http_message_t (调用者拥有), NULL 表示解析失败
 */
http_message_t *http_message_parse(const u_char *data, int len);

/*
 * http_message_free — 释放 HTTP 消息占用的所有内存
 */
void http_message_free(http_message_t *msg);

/*
 * http_message_print — 将消息格式化打印到 stdout
 */
void http_message_print(const http_message_t *msg);

/*
 * http_message_log — 生成单行结构化日志 (LOG_DEBUG)
 */
void http_message_log(const http_message_t *msg);

/* ── 辅助函数: 供 tcp_reassemble 用于消息边界检测 ── */

/*
 * http_detect_content_length — 从头部提取 Content-Length 值
 *   header_start: 头部区域起始地址
 *   header_len:   头部区域长度
 *   out_cl:       输出 Content-Length 值
 *   return: 1 找到, 0 未找到
 */
int http_detect_content_length(const char *header_start, int header_len,
                               int *out_cl);

/*
 * http_detect_chunked — 检测 Transfer-Encoding 是否包含 "chunked"
 *   return: 1 是 chunked, 0 不是
 */
int http_detect_chunked(const char *header_start, int header_len);

/*
 * http_detect_connection_close — 检测 Connection 头部是否为 "close"
 *   return: 1 是 close, 0 不是
 */
int http_detect_connection_close(const char *header_start, int header_len);

/*
 * http_chunked_body_complete — 扫描 chunked body 是否已完整接收
 *
 * 从 body 起始位置扫描所有 chunk, 检查终止零长度块是否已到达。
 *
 *   body_start:      header 之后的第一个字节
 *   body_len:        可用的 body 字节数
 *   out_decoded_len: 若完整, 输出解码后的 body 长度 (所有 chunk 数据之和)
 *   out_raw_len:     若完整, 输出原始字节消费量 (含 chunk framing)
 *   return: 1 完整, 0 需要更多数据, -1 解析错误
 */
int http_chunked_body_complete(const u_char *body_start, int body_len,
                               int *out_decoded_len, int *out_raw_len);

#endif /* HTTP_PARSER_H */
