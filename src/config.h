#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdint.h>

#include "parson.h"

typedef struct bud_config_s bud_config_t;

struct bud_config_s {
  /* Options from config file */
  uint16_t port;
  const char* host;
  const char* cert_file;
  const char* key_file;
  const char* ca_file;

  /* Various */

  /* Internal, just to keep stuff allocated */
  JSON_Value* json;
};

bud_config_t* bud_config_cli_load(int argc, char** argv);
bud_config_t* bud_config_load(const char* path);
void bud_config_free(bud_config_t* config);

#endif  /* SRC_CONFIG_H_ */
