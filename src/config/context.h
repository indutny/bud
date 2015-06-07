#ifndef SRC_CONFIG_CONTEXT_H_
#define SRC_CONFIG_CONTEXT_H_

#include "src/config.h"
#include "src/config/utils.h"
#include "src/common.h"

bud_error_t bud_context_load_cert(bud_context_t* context,
                                  const char* cert_file);
bud_error_t bud_context_load_key(bud_context_t* context,
                                 const char* key_file,
                                 const char* key_pass);
bud_error_t bud_context_load_keys(bud_context_t* context);

#endif  /* SRC_CONFIG_CONTEXT_H_ */
