#ifndef SRC_LOGGER_H_
#define SRC_LOGGER_H_

#include "error.h"
#include "config.h"

typedef struct bud_logger_s bud_logger_t;

struct bud_logger_s {
};

bud_error_t bud_logger_new(bud_config_t* config);
void bud_logger_free(bud_config_t* logger);

#endif  /* SRC_LOGGER_H_ */
