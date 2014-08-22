#ifndef SRC_LOGGER_H_
#define SRC_LOGGER_H_

#include "bud/logger.h"
#include "error.h"
#include "config.h"

typedef struct bud_logger_s bud_logger_t;

struct bud_logger_s {
  bud_log_level_t level;
  int stdio_enabled;
  int syslog_enabled;
};

bud_logger_t* bud_logger_new(bud_config_t* config, bud_error_t* err);
void bud_logger_free(bud_logger_t* logger);

void bud_clog(bud_config_t* config,
              bud_log_level_t level,
              const char* fmt,
              ...);
void bud_clogva(bud_config_t* config,
                bud_log_level_t level,
                const char* fmt,
                va_list ap);

#endif  /* SRC_LOGGER_H_ */
