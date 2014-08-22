#ifndef INCLUDE_BUD_LOGGER_H_
#define INCLUDE_BUD_LOGGER_H_

#include "bud/common.h"

/* Forward declarations */
struct bud_logger_s;

typedef enum bud_log_level_e bud_log_level_t;

enum bud_log_level_e {
  kBudLogDebug = 0,
  kBudLogNotice = 1,
  kBudLogInfo = 2,
  kBudLogWarning = 3,
  kBudLogFatal = 4
};

BUD_EXPORT void bud_log(struct bud_logger_s* logger,
                        bud_log_level_t level,
                        const char* fmt,
                        ...);
BUD_EXPORT void bud_logva(struct bud_logger_s* logger,
                          bud_log_level_t level,
                          const char* fmt,
                          va_list ap);

#endif  /* INCLUDE_BUD_LOGGER_H_ */
