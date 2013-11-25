#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"

#include "server.h"

/* Forward declaration */
struct bud_config_s;

typedef struct bud_client_s bud_client_t;
typedef struct bud_client_side_s bud_client_side_t;
typedef enum bud_client_side_type_e bud_client_side_type_t;

enum bud_client_side_type_e {
  kBudFrontend,
  kBudBackend
};

struct bud_client_side_s {
  bud_client_side_type_t type;
  uv_tcp_t tcp;
  ringbuffer input;
  ringbuffer output;

  uv_write_t write_req;
  uv_shutdown_t shutdown_req;

  int shutdown_sent;
  int pending_shutdown;
  int pending_destroy;
  ssize_t pending_write;
};

struct bud_client_s {
  struct bud_config_s* config;

  SSL* ssl;

  /* Compact representation of both sides */
  bud_client_side_t frontend;
  bud_client_side_t backend;

  /* State */
  uv_connect_t connect_req;
  int destroying;
  int destroy_waiting;
};

void bud_client_create(bud_config_t* config, uv_stream_t* stream);

#endif  /* SRC_CLIENT_H_ */
