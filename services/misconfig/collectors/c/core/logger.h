/**
 * logger.h - Centralized logging system
 */

#ifndef SHIELDX_LOGGER_H
#define SHIELDX_LOGGER_H

#include <stdio.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_t;

// Initialize logger
void log_init(log_level_t level);

// Log functions
void log_debug(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_fatal(const char *fmt, ...);

// Cleanup
void log_cleanup(void);

#endif // SHIELDX_LOGGER_H