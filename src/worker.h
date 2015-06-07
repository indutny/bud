#ifndef SRC_WORKER_H_
#define SRC_WORKER_H_

#include "src/config.h"
#include "src/error.h"

bud_error_t bud_worker(bud_config_t* config);
bud_error_t bud_worker_finalize(bud_config_t* config);

#endif  /* SRC_WORKER_H_ */
