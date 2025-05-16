#include "logging.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void nfsp_log(nfsp_log_level_t level, const char *func, const char *format,
              ...) {

    (void)func; // Unused parameter

    va_list args;
    va_start(args, format);

    char level_str[10];
    char ascii_color_str[10];
    switch (level) {
    case NFSP_LOG_LEVEL_ERROR:
        snprintf(level_str, sizeof(level_str), "err");
        snprintf(ascii_color_str, sizeof(ascii_color_str), "\033[31m"); // Red
        break;
    case NFSP_LOG_LEVEL_WARNING:
        snprintf(level_str, sizeof(level_str), "warn");
        snprintf(ascii_color_str, sizeof(ascii_color_str),
                 "\033[33m"); // Yellow
        break;
    case NFSP_LOG_LEVEL_INFO:
        snprintf(level_str, sizeof(level_str), "info");
        snprintf(ascii_color_str, sizeof(ascii_color_str), "\033[34m"); // Blue
        break;
    case NFSP_LOG_LEVEL_DEBUG:
        snprintf(level_str, sizeof(level_str), "debug");
        snprintf(ascii_color_str, sizeof(ascii_color_str),
                 "\033[35m"); // Purple
        break;
    case NFSP_LOG_LEVEL_SUCCESS:
        snprintf(level_str, sizeof(level_str), "succ");
        snprintf(ascii_color_str, sizeof(ascii_color_str),
                 "\033[32m"); // Green
        break;
    default:
        snprintf(level_str, sizeof(level_str), "info");
        snprintf(ascii_color_str, sizeof(ascii_color_str), "\033[34m"); // Blue
        break;
    }

    // format: "hh:ss:ms [level]: message"
    char time_str[20];
    time_t now         = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    fprintf(stderr, "%s [\033[1m%s%s\033[0m]: ", time_str, ascii_color_str,
            level_str);
    fprintf(stderr, "\033[0m"); // Reset color

    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");

    va_end(args);
}