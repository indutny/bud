#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdint.h>

#include "uv.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "common.h"
#include "error.h"

/* Forward declarations */
struct bud_server_s;
struct bud_worker_s;
struct bud_logger_s;
struct bud_http_pool_s;

typedef struct bud_context_s bud_context_t;
typedef struct bud_config_http_pool_s bud_config_http_pool_t;
typedef struct bud_config_s bud_config_t;

int kBudSSLClientIndex;
int kBudSSLSNIIndex;

struct bud_context_s {
  /* From config file */
  const char* servername;
  int servername_len;

  const char* cert_file;
  const char* key_file;
  const JSON_Array* npn;
  const char* ciphers;

  /* Various */
  SSL_CTX* ctx;
  char* npn_line;
  size_t npn_line_len;
};

struct bud_config_http_pool_s {
  int enabled;

  uint16_t port;
  const char* host;
  const char* query_fmt;

  /* internal */
  struct bud_http_pool_s* pool;
};

struct bud_config_s {
  /* Internal, just to keep stuff allocated */
  JSON_Value* json;

  /* Just internal things */
  uv_loop_t* loop;
  int argc;
  char** argv;
  char exepath[1024];
  struct bud_server_s* server;
  struct bud_logger_s* logger;

  /* Master state */
  struct {
    uv_signal_t sigterm;
    uv_signal_t sigint;
  } signal;
  struct bud_worker_s* workers;
  int last_worker;
  int pending_accept;

  /* Worker state */
  uv_pipe_t ipc;

  /* Used by client.c */
  char proxyline_fmt[256];

  /* Options from config file */
  int worker_count;
  int restart_timeout;
  int is_daemon;
  int is_worker;
  struct {
    const char* level;
    const char* facility;
    int stdio;
    int syslog;
  } log;

  struct {
    uint16_t port;
    const char* host;
    int proxyline;
    int keepalive;
    const char* security;
    int server_preference;
    const JSON_Array* npn;
    const char* ciphers;
    const char* cert_file;
    const char* key_file;
    int reneg_window;
    int reneg_limit;
    int ssl3;

    /* internal */
    struct sockaddr_storage addr;
    const SSL_METHOD* method;
  } frontend;

  struct {
    uint16_t port;
    const char* host;
    int keepalive;

    /* internal */
    struct sockaddr_storage addr;
  } backend;

  bud_config_http_pool_t sni;
  bud_config_http_pool_t stapling;

  int context_count;
  bud_context_t contexts[1];
};

bud_config_t* bud_config_cli_load(uv_loop_t* loop,
                                  int argc,
                                  char** argv,
                                  bud_error_t* err);
bud_config_t* bud_config_load(uv_loop_t* loop,
                              const char* path,
                              bud_error_t* err);
void bud_config_free(bud_config_t* config);
void bud_context_free(bud_context_t* context);

/* Helper for loading SNI */
bud_error_t bud_config_new_ssl_ctx(bud_config_t* config,
                                   bud_context_t* context);

/* Helper for http-pool.c */
int bud_config_str_to_addr(const char* host,
                           uint16_t port,
                           struct sockaddr_storage* addr);

#endif  /* SRC_CONFIG_H_ */
