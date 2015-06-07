#ifndef SRC_CLIENT_H_
#define SRC_CLIENT_H_

#include "uv.h"
#include "openssl/ssl.h"

#include "src/client-common.h"
#include "src/server.h"
#include "src/http-pool.h"

/* Forward declaration */
struct bud_config_s;
struct bud_config_backend_s;
struct bud_config_backend_list_s;

typedef struct bud_client_s bud_client_t;
typedef struct bud_client_host_s bud_client_host_t;

struct bud_client_host_s {
  char host[INET6_ADDRSTRLEN];
  unsigned int host_len;
  unsigned char family;
  uint16_t port;
};

struct bud_client_s {
  struct bud_config_s* config;

  SSL* ssl;
  uint64_t id;

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

  /* TLS Hello Data */
  bud_client_progress_t async_hello;
  struct {
    const char* servername;
    size_t servername_len;
    unsigned int ocsp_request:1;
  } hello;

  /* SNI */
  bud_http_request_t* sni_req;
  bud_context_t sni_ctx;

  /* Stapling */
  bud_http_request_t* stapling_cache_req;
  bud_http_request_t* stapling_req;
  bud_context_pkey_type_t stapling_type;
  char* stapling_ocsp_resp;
  size_t stapling_ocsp_resp_len;

  /* Availability */
  bud_client_progress_t retry;
  bud_config_balance_t balance;
  struct bud_config_backend_list_s* backend_list;
  struct bud_config_backend_s* selected_backend;
  uv_timer_t retry_timer;
  int retry_count;

  /* Balancing */
  bud_client_host_t local;

  /* Tracing and proxyline */
  bud_client_host_t remote;
  unsigned int proxyline_waiting;

  /* XForward */
  struct {
    size_t skip;
    unsigned char crlf;
  } xforward;
};

void bud_client_create(bud_config_t* config, uv_stream_t* stream);

#endif  /* SRC_CLIENT_H_ */
