#ifndef SRC_CONFIG_TRACING_H_
#define SRC_CONFIG_TRACING_H_

#include "parson.h"

#include "src/config.h"
#include "src/common.h"

bud_error_t bud_config_load_tracing(bud_config_trace_t* trace,
                                    JSON_Object* obj);
bud_error_t bud_config_init_tracing(bud_config_trace_t* trace);
void bud_config_trace_free(bud_config_trace_t* trace);

#endif  /* SRC_CONFIG_TRACING_H_ */
