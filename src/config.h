#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdint.h>

#include "uv.h"
#include "openssl/bio.h"
#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
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
typedef enum bud_config_balance_e bud_config_balance_t;
typedef struct bud_config_s bud_config_t;
typedef struct bud_config_addr_s bud_config_addr_t;
typedef enum bud_config_proxyline_s bud_config_proxyline_t;
typedef struct bud_config_backend_s bud_config_backend_t;
typedef struct bud_config_frontend_s bud_config_frontend_t;

int kBudSSLConfigIndex;
int kBudSSLClientIndex;
int kBudSSLSNIIndex;
int kBudSSLTicketKeyIndex;

struct bud_config_http_pool_s {
  int enabled;

  uint16_t port;
  const char* host;
  const char* url;

  /* internal */
  struct bud_http_pool_s* pool;
};

#define BUD_COMMON_SSL_FIELDS                                                 \
    const char* cert_file;                                                    \
    const char* key_file;                                                     \
    const JSON_Array* npn;                                                    \
    const char* ciphers;                                                      \
    const char* ecdh;                                                         \
    const char* ticket_key;                                                   \
    int request_cert;                                                         \
    const char* ca_file;                                                      \
    const JSON_Array* ca_array;                                               \
    /* internal */                                                            \
    char ticket_key_storage[48];                                              \
    char* npn_line;                                                           \
    size_t npn_line_len;                                                      \


#define BUD_CONFIG_ADDR_FIELDS                                                \
    uint16_t port;                                                            \
    const char* host;                                                         \
    int keepalive;                                                            \
    /* internal */                                                            \
    struct sockaddr_storage addr;

struct bud_config_addr_s {
  BUD_CONFIG_ADDR_FIELDS
};

struct bud_config_frontend_s {
  /* Inheritance */
  BUD_CONFIG_ADDR_FIELDS

  /* Public */
  const char* security;
  int server_preference;
  BUD_COMMON_SSL_FIELDS
  int reneg_window;
  int reneg_limit;
  int ssl3;
  int max_send_fragment;
  int allow_half_open;

  /* Internal */
  const SSL_METHOD* method;
  X509_STORE* ca_store;
};

enum bud_config_proxyline_s {
  kBudProxylineNone,
  kBudProxylineHAProxy,
  kBudProxylineJSON
};

struct bud_config_backend_s {
  /* Inheritance */
  BUD_CONFIG_ADDR_FIELDS

  /* Public */
  bud_config_proxyline_t proxyline;
  int xforward;

  /* Internal */
  bud_config_t* config;
  int dead;
  uint64_t last_checked;
  uint64_t dead_since;
  uv_timer_t* revive_timer;
};

#undef BUD_CONFIG_ADDR_FIELDS

struct bud_context_s {
  /* From config file */
  const char* servername;
  size_t servername_len;

  BUD_COMMON_SSL_FIELDS
  bud_config_backend_t* backend;

  /* Various */
  SSL_CTX* ctx;
  X509* cert;
  X509* issuer;
  X509_STORE* ca_store;
  OCSP_CERTID* ocsp_id;
  char* ocsp_der_id;
  size_t ocsp_der_id_len;
  const char* ocsp_url;
  size_t ocsp_url_len;
  bud_config_backend_t backend_st;
};

#undef BUD_COMMON_SSL_FIELDS

enum bud_config_balance_e {
  kBudBalanceRoundRobin,
  kBudBalanceSNI
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
    uv_signal_t* sigterm;
    uv_signal_t* sigint;

    /* NOTE: shared with worker */
    uv_signal_t* sighup;
  } signal;
  struct bud_worker_s* workers;
  int last_worker;
  int pending_accept;

  /* Worker state */
  uv_pipe_t* ipc;

  /* Used by client.c */
  struct {
    char haproxy[256];
    char json[256];
  } proxyline_fmt;
  bud_config_balance_t balance_e;

  /* Options from config file */
  int inlined;
  char* path;

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
    int death_timeout;
    int revive_interval;
    int retry_interval;
    int max_retries;
  } availability;

  bud_config_frontend_t frontend;
  bud_config_backend_t* backend;
  const char* balance;
  int backend_count;
  int last_backend;
#ifndef _WIN32
  uid_t user;
  gid_t group;
#endif
  bud_config_http_pool_t sni;
  bud_config_http_pool_t stapling;

  int context_count;
  bud_context_t* contexts;
};

bud_config_t* bud_config_cli_load(int argc, char** argv, bud_error_t* err);
bud_config_t* bud_config_load(const char* path, int inlined, bud_error_t* err);
bud_error_t bud_config_reload(bud_config_t* config);
void bud_config_free(bud_config_t* config);
void bud_context_free(bud_context_t* context);

/* Helper for loading SNI */
bud_error_t bud_config_new_ssl_ctx(bud_config_t* config,
                                   bud_context_t* context);
bud_error_t bud_config_load_backend(bud_config_t* config,
                                    JSON_Object* obj,
                                    bud_config_backend_t* backend);

/* Helper for stapling */
bud_context_t* bud_config_select_context(bud_config_t* config,
                                         const char* servername,
                                         size_t servername_len);
const char* bud_context_get_ocsp_id(bud_context_t* context,
                                    size_t* size);
const char* bud_context_get_ocsp_req(bud_context_t* context,
                                     size_t* size,
                                     char** ocsp_request,
                                     size_t* ocsp_request_len);

/* Helper for http-pool.c */
int bud_config_str_to_addr(const char* host,
                           uint16_t port,
                           struct sockaddr_storage* addr);

/* Helper for SNI and stapling */
int bud_context_use_certificate_chain(bud_context_t* ctx, BIO *in);

void bud_config_drop_privileges(bud_config_t* config);

#endif  /* SRC_CONFIG_H_ */
