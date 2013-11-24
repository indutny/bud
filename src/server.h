#ifndef SRC_SERVER_H_
#define SRC_SERVER_H_

#include "uv.h"

#include "config.h"
#include "error.h"

typedef struct bud_server_s bud_server_t;

struct bud_server_s {
  bud_config_t* config;
  uv_tcp_t tcp;
  struct sockaddr_storage frontend;
  struct sockaddr_storage backend;
  char proxyline_fmt[256];
};

bud_error_t bud_server_new(bud_config_t* config);
void bud_server_destroy(bud_server_t* server);

#endif  /* SRC_SERVER_H_ */
