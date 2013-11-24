#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"

#include "server.h"

/* Forward declaration */
struct bud_config_s;

typedef struct bud_client_s bud_client_t;

struct bud_client_s {
  struct bud_config_s* config;

  uv_tcp_t tcp_in;
  uv_tcp_t tcp_out;
  ringbuffer enc_in;
  ringbuffer enc_out;
  ringbuffer clear_in;
  ringbuffer clear_out;

  SSL* ssl;

  /* State */
  uv_connect_t connect_req;
  int destroying;
  int shutdown;
  int destroy_waiting;
  ssize_t current_enc_write;
  ssize_t current_clear_write;
  int current_enc_waiting;
  int current_clear_waiting;
  uv_write_t enc_write_req;
  uv_write_t clear_write_req;
};

void bud_client_create(bud_config_t* config, uv_stream_t* stream);

#endif  /* SRC_CLIENT_H_ */
