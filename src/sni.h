#ifndef SRC_SNI_H_
#define SRC_SNI_H_

#include "parson.h"

#include "src/error.h"
#include "src/config.h"

bud_error_t bud_sni_from_json(bud_config_t* config,
                              struct json_value_t* json,
                              bud_context_t* ctx);

#endif  /* SRC_SNI_H_ */
