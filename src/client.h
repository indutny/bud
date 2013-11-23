#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"

#include "server.h"

typedef struct bud_client_s bud_client_t;

struct bud_client_s {
  uv_tcp_t tcp_in;
  ringbuffer enc_in;
  ringbuffer enc_out;
  ringbuffer clear_out;

  SSL* ssl;

  /* State */
  int destroying;
  ssize_t current_enc_write;
  ssize_t current_clear_write;
  uv_write_t enc_write_req;
  uv_write_t clear_write_req;
};

void bud_client_create(bud_server_t* server);

#endif  /* SRC_CLIENT_H_ */
