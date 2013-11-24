#ifndef SRC_MASTER_H_
#define SRC_MASTER_H_

#include "config.h"
#include "error.h"

bud_error_t bud_master(bud_config_t* config);
bud_error_t bud_master_finalize(bud_config_t* config);

#endif  /* SRC_MASTER_H_ */
