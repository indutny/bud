#ifndef INCLUDE_BUD_TRACING_H_
#define INCLUDE_BUD_TRACING_H_

#include "bud/error.h"  /* bud_error_t */
#include <stdint.h>  /* uint16_t */

/* Forward declarations */
struct ssl_st;

typedef struct bud_trace_module_s bud_trace_module_t;
typedef struct bud_trace_client_s bud_trace_client_t;
typedef struct bud_trace_backend_s bud_trace_backend_t;
typedef enum bud_trace_balance_e bud_trace_balance_t;

typedef void (*bud_trace_cb_t)(bud_trace_client_t* client);
typedef void (*bud_trace_backend_cb_t)(bud_trace_client_t* client,
                                       bud_trace_backend_t* backend);
typedef void (*bud_trace_error_cb_t)(bud_trace_client_t* client,
                                     bud_error_t err);

#define CONNECTION_FIELDS                                                     \
    int fd;                                                                   \
    uint16_t port;                                                            \
    const char* host;                                                         \

enum bud_trace_balance_e {
  kBudTraceBalanceRoundRobin,
  kBudTraceBalanceSNI,
  kBudTraceBalanceOnFail
};

struct bud_trace_client_s {
  CONNECTION_FIELDS

  /* OpenSSL's SSL* object */
  struct ssl_st* ssl;

  /* Circularly-monotonic semi-unique connection id */
  uint64_t id;
};

struct bud_trace_backend_s {
  CONNECTION_FIELDS

  bud_trace_balance_t balance;
  const char* balance_str;
  int sni_match;
};

#undef CONNECTION_FIELDS

/* All tracing functions */
#define BUD_TRACING_ENUM(X)                                                   \
    BUD_TRACING_CLIENT_ENUM(X)                                                \
    BUD_TRACING_BACKEND_ENUM(X)                                               \
    BUD_TRACING_ERROR_ENUM(X)                                                 \

/* Tracing functions that do accept only one argument: client */
#define BUD_TRACING_CLIENT_ENUM(X)                                            \
    X(frontend_accept)                                                        \
    X(end)                                                                    \
    X(handshake)                                                              \
    X(retry)                                                                  \

/* Tracing functions that do accept two arguments: client, backend */
#define BUD_TRACING_BACKEND_ENUM(X)                                           \
    X(backend_connect)                                                        \
    X(kill_backend)                                                           \
    X(revive_backend)                                                         \

/* Tracing functions that do accept two arguments: client, err */
#define BUD_TRACING_ERROR_ENUM(X)                                             \
    X(error)                                                                  \

#define BUD_TRACE_MODULE_CLIENT_DECL(V) bud_trace_cb_t V;
#define BUD_TRACE_MODULE_BACKEND_DECL(V) bud_trace_backend_cb_t V;
#define BUD_TRACE_MODULE_ERROR_DECL(V) bud_trace_error_cb_t V;

struct bud_trace_module_s {
  int version;
  BUD_TRACING_CLIENT_ENUM(BUD_TRACE_MODULE_CLIENT_DECL)
  BUD_TRACING_BACKEND_ENUM(BUD_TRACE_MODULE_BACKEND_DECL)
  BUD_TRACING_ERROR_ENUM(BUD_TRACE_MODULE_ERROR_DECL)
};

#undef BUD_TRACE_MODULE_CLIENT_DECL
#undef BUD_TRACE_MODULE_BACKEND_DECL
#undef BUD_TRACE_MODULE_ERROR_DECL

/* Convenient define for a module declaration */
#define BUD_TRACE_MODULE bud_trace_module_t bud_trace_module
#define BUD_TRACE_VERSION 1

#endif  /* INCLUDE_BUD_TRACING_H_ */
