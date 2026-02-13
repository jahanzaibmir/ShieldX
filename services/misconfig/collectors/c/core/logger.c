/**
 * logger.c - Centralized logging implementation
 */

#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

static log_level_t g_log_level = LOG_LEVEL_INFO;
static FILE *g_log_file = NULL;

static const char *level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

#ifdef _WIN32
static WORD level_colors[] = {
    FOREGROUND_INTENSITY,                                           // DEBUG: gray
    FOREGROUND_GREEN | FOREGROUND_INTENSITY,                       // INFO: bright green
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,      // WARN: yellow
    FOREGROUND_RED | FOREGROUND_INTENSITY,                         // ERROR: bright red
    FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY        // FATAL: magenta
};
#else
static const char *level_colors[] = {
    "\x1b[90m",      // DEBUG: gray
    "\x1b[92m",      // INFO: bright green
    "\x1b[93m",      // WARN: yellow
    "\x1b[91m",      // ERROR: bright red
    "\x1b[95m"       // FATAL: magenta
};
static const char *color_reset = "\x1b[0m";
#endif

void log_init(log_level_t level) {
    g_log_level = level;
    g_log_file = stderr;
    
    // Could add file logging here if needed
    // g_log_file = fopen("shieldx.log", "a");
}

static void log_message(log_level_t level, const char *fmt, va_list args) {
    if (level < g_log_level || !g_log_file) {
        return;
    }
    
    // Get timestamp
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
#ifdef _WIN32
    HANDLE console = GetStdHandle(STD_ERROR_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console, &csbi);
    WORD old_attrs = csbi.wAttributes;
    
    // Print timestamp and level with color
    SetConsoleTextAttribute(console, level_colors[level]);
    fprintf(g_log_file, "[%s] [%s] ", timestamp, level_strings[level]);
    SetConsoleTextAttribute(console, old_attrs);
    
    // Print message
    vfprintf(g_log_file, fmt, args);
    fprintf(g_log_file, "\n");
#else
    // Print with ANSI colors on Unix
    fprintf(g_log_file, "%s[%s] [%s]%s ", 
            level_colors[level], timestamp, level_strings[level], color_reset);
    vfprintf(g_log_file, fmt, args);
    fprintf(g_log_file, "\n");
#endif
    
    fflush(g_log_file);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_DEBUG, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_INFO, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_WARN, fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_ERROR, fmt, args);
    va_end(args);
}

void log_fatal(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_FATAL, fmt, args);
    va_end(args);
}

void log_cleanup(void) {
    if (g_log_file && g_log_file != stderr && g_log_file != stdout) {
        fclose(g_log_file);
    }
    g_log_file = NULL;
}