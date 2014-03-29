#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include "uv.h"
#include "openssl/ssl.h"

#include "client-common.h"
#include "hello-parser.h"
#include "server.h"
#include "http-pool.h"

/* Forward declaration */
struct bud_config_s;
struct bud_config_backend_s;

typedef struct bud_client_s bud_client_t;

struct bud_client_s {
  struct bud_config_s* config;

  SSL* ssl;

  /* Renegotiation attack prevention */
  uint64_t last_handshake;
  int handshakes;

  /* Compact representation of both sides */
  bud_client_side_t frontend;
  bud_client_side_t backend;

  /* State */
  uv_connect_t connect_req;
  bud_client_progress_t connect;
  bud_client_progress_t close;
  bud_client_progress_t cycle;
  int recycle;
  int destroy_waiting;

  /* Client hello parser */
  bud_client_progress_t hello_parse;
  bud_client_hello_t hello;

  /* SNI */
  bud_http_request_t* sni_req;
  bud_context_t sni_ctx;

  /* Stapling */
  bud_http_request_t* stapling_cache_req;
  bud_http_request_t* stapling_req;
  char* stapling_ocsp_resp;
  size_t stapling_ocsp_resp_len;

  /* Availability */
  bud_client_progress_t retry;
  struct bud_config_backend_s* selected_backend;
  uv_timer_t retry_timer;
  int retry_count;

  /* Tracing and proxyline */
  char* proxyline;
  size_t proxyline_len;
  char host[INET6_ADDRSTRLEN];
  unsigned char family;
  uint16_t port;
};

void bud_client_create(bud_config_t* config, uv_stream_t* stream);

#endif  /* SRC_CLIENT_H_ */
