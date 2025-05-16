#ifndef NFSP_LOGGING_H
#define NFSP_LOGGING_H

typedef enum {
    NFSP_LOG_LEVEL_ERROR,
    NFSP_LOG_LEVEL_WARNING,
    NFSP_LOG_LEVEL_INFO,
    NFSP_LOG_LEVEL_DEBUG,
    NFSP_LOG_LEVEL_SUCCESS,
} nfsp_log_level_t;

#define NFSP_ERROR(fmt, ...)                                                   \
    nfsp_log(NFSP_LOG_LEVEL_ERROR, __func__, fmt, ##__VA_ARGS__)
#define NFSP_WARNING(fmt, ...)                                                 \
    nfsp_log(NFSP_LOG_LEVEL_WARNING, __func__, fmt, ##__VA_ARGS__)
#define NFSP_INFO(fmt, ...)                                                    \
    nfsp_log(NFSP_LOG_LEVEL_INFO, __func__, fmt, ##__VA_ARGS__)
#define NFSP_DEBUG(fmt, ...)                                                   \
    nfsp_log(NFSP_LOG_LEVEL_DEBUG, __func__, fmt, ##__VA_ARGS__)
#define NFSP_SUCCESS(fmt, ...)                                                 \
    nfsp_log(NFSP_LOG_LEVEL_SUCCESS, __func__, fmt, ##__VA_ARGS__)

void nfsp_log(nfsp_log_level_t level, const char *func, const char *format,
              ...);

#endif // NFSP_LOGGING_H