#ifndef SRC_SERVER_H_
#define SRC_SERVER_H_

#include "uv.h"

#include "src/config.h"
#include "src/error.h"

typedef struct bud_server_s bud_server_t;

struct bud_server_s {
  bud_config_t* config;
  uv_tcp_t tcp;
  int pending_accept;

  bud_server_t* prev;
};

bud_error_t bud_create_servers(bud_config_t* config);
void bud_free_servers(bud_config_t* config);

#endif  /* SRC_SERVER_H_ */
