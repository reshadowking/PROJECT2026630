/*
 * logger.c — 线程安全日志模块
 *
 * 功能:
 *   多级别日志输出 (DEBUG/INFO/WARN/ERROR) 到 stderr,
 *   使用环形缓冲区 + 定时刷盘减少 I/O 开销。
 *
 * 编译时可通过 -DLOG_ACTIVE_LEVEL=LOG_LEVEL_DEBUG 控制最低输出级别
 */

#include "logger.h"
#include "common.h"
#include <stdarg.h>
#include <string.h>

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *log_fp = NULL;
static char log_buf[LOG_BUF_SZ];
static int log_buf_used = 0;
static time_t log_last_flush = 0;

/*
 * log_write — 写入一条日志
 *
 * 格式: [HH:MM:SS.ms] [LEVEL] [tid:TID] [file:line] message
 *
 * 使用内部缓冲区减少 fwrite 调用频率,
 * 缓冲区满 512B 或距上次刷盘超过 1s 时自动刷盘。
 *
 *   level: 日志级别字符串 ("DEBUG"/"INFO"/"WARN"/"ERROR")
 *   file:  源文件名
 *   line:  行号
 *   fmt:   格式化字符串
 *   ...:   可变参数
 */
void log_write(const char *level, const char *file, int line, const char *fmt, ...)
{
    pthread_mutex_lock(&log_mutex);

    if (!log_fp) {
        log_fp = stderr;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_buf;
    localtime_r(&ts.tv_sec, &tm_buf);

    int room = LOG_BUF_SZ - log_buf_used;
    if (room < 256) {
        fwrite(log_buf, 1, (size_t)log_buf_used, log_fp);
        fflush(log_fp);
        log_buf_used = 0;
        room = LOG_BUF_SZ;
    }

    int n = snprintf(log_buf + log_buf_used, (size_t)room,
                     "[%02d:%02d:%02d.%03ld] [%s] [tid:%ld] [%s:%d] ",
                     tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, ts.tv_nsec / 1000000,
                     level,
                     (long)syscall(SYS_gettid),
                     file, line);
    if (n > 0 && n < room) log_buf_used += n;
    else { log_buf_used = LOG_BUF_SZ; goto flush_now; }

    va_list args;
    va_start(args, fmt);
    int m = vsnprintf(log_buf + log_buf_used, (size_t)(LOG_BUF_SZ - log_buf_used), fmt, args);
    va_end(args);
    if (m > 0 && log_buf_used + m < LOG_BUF_SZ) log_buf_used += m;
    else { log_buf_used = LOG_BUF_SZ; goto flush_now; }

    if (log_buf_used + 2 < LOG_BUF_SZ) {
        log_buf[log_buf_used++] = '\n';
    }

    if (log_buf_used > LOG_BUF_SZ - 512 || (ts.tv_sec - log_last_flush) >= 1) {
flush_now:
        if (log_buf_used > 0) {
            fwrite(log_buf, 1, (size_t)log_buf_used, log_fp);
            fflush(log_fp);
            log_buf_used = 0;
        }
        log_last_flush = ts.tv_sec;
    }

    pthread_mutex_unlock(&log_mutex);
}

/*
 * log_flush — 强制刷盘所有缓冲日志
 */
void log_flush(void)
{
    pthread_mutex_lock(&log_mutex);
    if (log_buf_used > 0 && log_fp) {
        fwrite(log_buf, 1, (size_t)log_buf_used, log_fp);
        fflush(log_fp);
        log_buf_used = 0;
    }
    log_last_flush = time(NULL);
    pthread_mutex_unlock(&log_mutex);
}
