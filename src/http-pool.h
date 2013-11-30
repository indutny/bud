#ifndef SRC_HTTP_POOL_H_
#define SRC_HTTP_POOL_H_

#include "uv.h"
#include "http_parser.h"
#include "ringbuffer.h"
#include "parson.h"

#include "config.h"
#include "queue.h"
#include "error.h"

#define BUD_HTTP_REQUEST_BUF_SIZE 8096

typedef struct bud_http_pool_s bud_http_pool_t;
typedef struct bud_http_request_s bud_http_request_t;
typedef enum bud_http_request_state_e bud_http_request_state_t;
typedef void (*bud_http_cb)(bud_http_request_t* req, bud_error_t err);

enum bud_http_request_state_e {
  kBudHttpConnecting,
  kBudHttpConnected,
  kBudHttpRunning,
  kBudHttpDisconnected
};

struct bud_http_pool_s {
  QUEUE pool;
  QUEUE reqs;

  bud_config_t* config;
  char* host;
  size_t host_len;
  struct sockaddr_storage addr;
  uint16_t port;
};

struct bud_http_request_s {
  QUEUE member;

  /* Pool state */
  bud_http_pool_t* pool;
  bud_http_request_state_t state;
  int complete;

  /* Connection */
  uv_tcp_t tcp;
  uv_connect_t connect;
  uv_write_t write;
  char buf[BUD_HTTP_REQUEST_BUF_SIZE];
  ringbuffer response_buf;
  http_parser parser;

  /* Request */
  char* url;
  size_t url_len;
  bud_http_cb cb;
  void* data;
  JSON_Value* response;
};

bud_http_pool_t* bud_http_pool_new(bud_config_t* config,
                                   const char* host,
                                   uint16_t port,
                                   bud_error_t* err);
void bud_http_pool_free(bud_http_pool_t* pool);

bud_http_request_t* bud_http_request(bud_http_pool_t* pool,
                                     const char* fmt,
                                     const char* arg,
                                     bud_http_cb cb,
                                     bud_error_t* err);
void bud_http_request_cancel(bud_http_request_t* request);

#endif  /* SRC_HTTP_POOL_H_ */
