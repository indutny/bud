#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"

#include "hello-parser.h"
#include "server.h"
#include "redis.h"

/* Forward declaration */
struct bud_config_s;

typedef struct bud_client_s bud_client_t;
typedef struct bud_client_side_s bud_client_side_t;
typedef enum bud_client_side_type_e bud_client_side_type_t;
typedef enum bud_client_progress_e bud_client_progress_t;

enum bud_client_side_type_e {
  kBudFrontend,
  kBudBackend
};

enum bud_client_progress_e {
  kBudProgressNone,
  kBudProgressRunning,
  kBudProgressDone
};

struct bud_client_side_s {
  bud_client_side_type_t type;
  uv_tcp_t tcp;
  ringbuffer input;
  ringbuffer output;

  uv_write_t write_req;
  uv_shutdown_t shutdown_req;

  bud_client_progress_t reading;
  bud_client_progress_t shutdown;
  bud_client_progress_t close;
  bud_client_progress_t write;

  size_t write_size;
};

struct bud_client_s {
  struct bud_config_s* config;

  SSL* ssl;

  /* Compact representation of both sides */
  bud_client_side_t frontend;
  bud_client_side_t backend;

  /* State */
  uv_connect_t connect_req;
  bud_client_progress_t close;
  int destroy_waiting;

  /* Client hello parser */
  bud_client_progress_t hello_parse;
  bud_client_hello_t hello;
  bud_redis_sni_t* sni_req;
};

void bud_client_create(bud_config_t* config, uv_stream_t* stream);

#endif  /* SRC_CLIENT_H_ */
