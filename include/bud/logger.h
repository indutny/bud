#ifndef INCLUDE_BUD_LOGGER_H_
#define INCLUDE_BUD_LOGGER_H_

#include "error.h"
#include "config.h"

typedef enum bud_log_level_e bud_log_level_t;
typedef struct bud_logger_s bud_logger_t;

enum bud_log_level_e {
  kBudLogDebug = 0,
  kBudLogNotice = 1,
  kBudLogInfo = 2,
  kBudLogWarning = 3,
  kBudLogFatal = 4
};

struct bud_logger_s {
  bud_log_level_t level;
  int stdio_enabled;
  int syslog_enabled;
};

bud_logger_t* bud_logger_new(bud_config_t* config, bud_error_t* err);
void bud_logger_free(bud_logger_t* logger);

void bud_log(bud_config_t* config, bud_log_level_t level, const char* fmt, ...);
void bud_logva(bud_config_t* config,
               bud_log_level_t level,
               const char* fmt,
               va_list ap);

#endif  /* INCLUDE_BUD_LOGGER_H_ */
