#ifndef SRC_LOGGER_H
#define SRC_LOGGER_H

#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3

#ifndef LOG_ACTIVE_LEVEL
#define LOG_ACTIVE_LEVEL LOG_LEVEL_INFO
#endif

void log_write(const char *level, const char *file, int line, const char *fmt, ...);
void log_flush(void);

#if LOG_ACTIVE_LEVEL <= LOG_LEVEL_ERROR
#define LOG_ERROR(fmt, ...) log_write("ERROR", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_ERROR(fmt, ...) ((void)0)
#endif

#if LOG_ACTIVE_LEVEL <= LOG_LEVEL_WARN
#define LOG_WARN(fmt, ...)  log_write("WARN",  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_WARN(fmt, ...)  ((void)0)
#endif

#if LOG_ACTIVE_LEVEL <= LOG_LEVEL_INFO
#define LOG_INFO(fmt, ...)  log_write("INFO",  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)  ((void)0)
#endif

#if LOG_ACTIVE_LEVEL <= LOG_LEVEL_DEBUG
#define LOG_DEBUG(fmt, ...) log_write("DEBUG", __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#endif
