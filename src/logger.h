#ifndef SRC_LOGGER_H_
#define SRC_LOGGER_H_

#include "error.h"
#include "config.h"

typedef enum bud_log_level_e bud_log_level_t;
typedef struct bud_logger_s bud_logger_t;

enum bud_log_level_e {
  kBudLogDebug = 0,
  kBudLogInfo = 1,
  kBudLogWarning = 2,
  kBudLogFatal = 3
};

struct bud_logger_s {
  bud_log_level_t level;
};

bud_error_t bud_logger_new(bud_config_t* config);
void bud_logger_free(bud_config_t* logger);

void bud_log(bud_config_t* config, bud_log_level_t level, char* fmt, ...);

#endif  /* SRC_LOGGER_H_ */
