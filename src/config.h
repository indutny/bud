#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <stdint.h>

#include "uv.h"
#include "openssl/bio.h"
#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "parson.h"

#include "bud/tracing.h"
#include "common.h"
#include "error.h"
#include "ipc.h"

/* Forward declarations */
struct bud_server_s;
struct bud_worker_s;
struct bud_logger_s;
struct bud_http_pool_s;

typedef struct bud_context_s bud_context_t;
typedef struct bud_config_http_pool_s bud_config_http_pool_t;
typedef enum bud_config_balance_e bud_config_balance_t;
typedef enum bud_context_pkey_type_e bud_context_pkey_type_t;
typedef struct bud_context_pem_s bud_context_pem_t;
typedef struct bud_config_trace_s bud_config_trace_t;
typedef struct bud_config_s bud_config_t;
typedef struct bud_config_addr_s bud_config_addr_t;
typedef enum bud_config_proxyline_s bud_config_proxyline_t;
typedef struct bud_config_backend_s bud_config_backend_t;
typedef struct bud_config_backend_list_s bud_config_backend_list_t;
typedef struct bud_config_frontend_s bud_config_frontend_t;
typedef struct bud_config_frontend_interface_s bud_config_frontend_interface_t;

int kBudSSLConfigIndex;
int kBudSSLClientIndex;
int kBudSSLSNIIndex;
int kBudSSLTicketKeyIndex;
const char* kPipedConfigPath;

struct bud_config_http_pool_s {
  int enabled;

  uint16_t port;
  const char* host;
  const char* url;

  /* internal */
  struct bud_http_pool_s* pool;
};


#define BUD_CONFIG_ADDR_FIELDS                                                \
    uint16_t port;                                                            \
    const char* host;                                                         \
    int keepalive;                                                            \
    /* internal */                                                            \
    struct sockaddr_storage addr;



struct bud_config_addr_s {
  BUD_CONFIG_ADDR_FIELDS
};

struct bud_config_frontend_interface_s {
  bud_config_addr_t* list;
  int count;
};

struct bud_config_frontend_s {
  /* Inheritance */
  BUD_CONFIG_ADDR_FIELDS

  /* Public */
  bud_config_frontend_interface_t interface;

  const char* security;
  int reneg_window;
  int reneg_limit;
  int ssl3;
  int max_send_fragment;
  int allow_half_open;

  /* Internal */
  const SSL_METHOD* method;
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

struct bud_config_backend_list_s {
  bud_config_backend_t* list;
  int count;
  int last;

  /* Map by ip */
  bud_hashmap_t external_map;
  unsigned int external_count;
};

enum bud_config_balance_e {
  kBudBalanceRoundRobin,
  kBudBalanceSNI,
  kBudBalanceOnFail,
  kBudBalanceExternal
};

enum bud_context_pkey_type_e {
  kBudContextPKeyRSA = 0x0,
  kBudContextPKeyECC = 0x1,
  kBudContextPKeyEnd = 0x2
};

struct bud_context_pem_s {
  X509* cert;
  X509* issuer;
  OCSP_CERTID* ocsp_id;
  char* ocsp_der_id;
  size_t ocsp_der_id_len;
  const char* ocsp_url;
  size_t ocsp_url_len;
};

#undef BUD_CONFIG_ADDR_FIELDS

struct bud_context_s {
  bud_config_t* config;

  /* From config file */
  const char* servername;
  size_t servername_len;
  bud_config_backend_list_t backend;

  const char* cert_file;
  const JSON_Array* cert_files;
  const char* key_file;
  const char* key_pass;
  const JSON_Array* key_files;
  const JSON_Array* key_passes;
  const JSON_Array* npn;
  const char* ciphers;
  const char* ecdh;
  const char* dh_file;
  const char* ticket_key;

  int ticket_timeout;
  int ticket_rotate;

  unsigned int ticket_key_on:1;
  unsigned int request_cert:1;
  unsigned int optional_cert:1;
  int server_preference:1;

  const char* ca_file;
  const JSON_Array* ca_array;

  /* Could be either `on-fail` or false */
  const char* balance;

  /* Various */
  SSL_CTX* ctx;
  bud_context_pem_t pem[kBudContextPKeyEnd];
  X509_STORE* ca_store;
  DH* dh;
  char ticket_key_storage[48];
  char* npn_line;
  size_t npn_line_len;
  bud_config_balance_t balance_e;
  uv_timer_t* rotate_timer;
};

#define BUD_CONFIG_TRACE_CLIENT_DECL(V) bud_trace_cb_t* V;
#define BUD_CONFIG_TRACE_BACKEND_DECL(V) bud_trace_backend_cb_t* V;
#define BUD_CONFIG_TRACE_CLOSE_DECL(V) bud_trace_close_cb_t* V;

struct bud_config_trace_s {
  /* DSO hooks for tracing */
  BUD_TRACING_CLIENT_ENUM(BUD_CONFIG_TRACE_CLIENT_DECL)
  BUD_TRACING_BACKEND_ENUM(BUD_CONFIG_TRACE_BACKEND_DECL)
  BUD_TRACING_CLOSE_ENUM(BUD_CONFIG_TRACE_CLOSE_DECL)

  JSON_Array* dso_array;
  uv_lib_t* dso;
  int dso_count;
};

#undef BUD_CONFIG_TRACE_CLIENT_DECL
#undef BUD_CONFIG_TRACE_BACKEND_DECL
#undef BUD_CONFIG_TRACE_CLOSE_DECL

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
  uint64_t client_id;

  /*
   * Map with a contents of every loaded file.
   * Primary used for syncing the files between master and workers
   */
  struct {
    bud_hashmap_t hashmap;
    char* str;
    size_t len;
  } files;

  /* Master state */
  struct {
    uv_signal_t* sigterm;
    uv_signal_t* sigint;

    /* NOTE: shared with worker */
    uv_signal_t* sighup;
  } signal;
  struct bud_worker_s* workers;
  int last_worker;

  /* Worker state, and master control IPC */
  bud_ipc_t ipc;

  /* Used by client.c */
  struct {
    char haproxy[256];
    char json[256];
  } proxyline_fmt;
  bud_config_balance_t balance_e;

  /* Options from config file */
  int piped_index;
  unsigned int piped:1;
  unsigned int inlined:1;
  const char* path;

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
  const char* balance;

  const char* user;
  const char* group;

  bud_config_http_pool_t sni;
  bud_config_http_pool_t stapling;

  int context_count;
  bud_context_t* contexts;

  bud_config_trace_t trace;
};

bud_error_t bud_config_new(int argc, char** argv, bud_config_t** out);
bud_error_t bud_config_load(bud_config_t* config);
void bud_config_free(bud_config_t* config);

/* Getting/Setting file cache */
bud_error_t bud_config_get_files(bud_config_t* config,
                                 const char** files,
                                 size_t* size);
bud_error_t bud_config_set_files(bud_config_t* config,
                                 const char* files,
                                 size_t size);
bud_error_t bud_config_reload_files(bud_config_t* config);

/* Helper for loading SNI */
bud_error_t bud_context_load(JSON_Object* obj,
                             bud_context_t* ctx);
bud_error_t bud_context_init(bud_config_t* config,
                             bud_context_t* context);
void bud_context_free(bud_context_t* context);

bud_error_t bud_config_load_backend_list(bud_config_t* config,
                                         JSON_Object* obj,
                                         bud_config_backend_list_t* backend);

/* Helper for stapling */
bud_context_t* bud_config_select_context(bud_config_t* config,
                                         const char* servername,
                                         size_t servername_len);
const char* bud_context_get_ocsp_id(bud_context_t* context,
                                    bud_context_pkey_type_t type,
                                    size_t* size);
const char* bud_context_get_ocsp_req(bud_context_t* context,
                                     bud_context_pkey_type_t type,
                                     size_t* size,
                                     char** ocsp_request,
                                     size_t* ocsp_request_len);

/* Helper for http-pool.c */
int bud_config_str_to_addr(const char* host,
                           uint16_t port,
                           struct sockaddr_storage* addr);

bud_error_t bud_config_drop_privileges(bud_config_t* config);

/* Helper for tracing */
const char* bud_config_balance_to_str(bud_config_balance_t balance);

/* Helper for client */
uint64_t bud_config_get_client_id(bud_config_t* config);
bud_context_pkey_type_t bud_config_pkey_type(EVP_PKEY* pkey);
bud_context_pkey_type_t bud_context_select_pkey(bud_context_t* context, SSL* s);

/* IPC helpers */
bud_error_t bud_config_set_ticket(bud_config_t* config, bud_ipc_msg_t* msg);

#endif  /* SRC_CONFIG_H_ */
