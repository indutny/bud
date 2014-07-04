#ifndef INCLUDE_BUD_TRACING_H_
#define INCLUDE_BUD_TRACING_H_

#include <stdint.h>  /* uint16_t */

/* Forward declarations */
struct ssl_st;

typedef struct bud_trace_module_s bud_trace_module_t;
typedef struct bud_trace_client_s bud_trace_client_t;
typedef struct bud_trace_backend_s bud_trace_backend_t;
typedef void (*bud_trace_cb_t)(bud_trace_client_t* client);
typedef void (*bud_trace_backend_cb_t)(bud_trace_client_t* client,
                                       bud_trace_backend_t* backend);

#define CONNECTION_FIELDS                                                     \
    int fd;                                                                   \
    uint16_t port;                                                            \
    const char* host;                                                         \

struct bud_trace_client_s {
  /* OpenSSL's SSL* object */
  struct ssl_st* ssl;

  CONNECTION_FIELDS
};

struct bud_trace_backend_s {
  CONNECTION_FIELDS
};

#undef CONNECTION_FIELDS

#define BUD_TRACING_ENUM(X)                                                   \
    X(frontend_accept)                                                        \
    X(backend_connect)                                                        \
    X(end)                                                                    \
    X(handshake)                                                              \

#define BUD_TRACE_MODULE_DECL(V) bud_trace_cb_t V;

struct bud_trace_module_s {
  BUD_TRACING_ENUM(BUD_TRACE_MODULE_DECL);
};

#undef BUD_TRACE_MODULE_DECL

#endif  /* INCLUDE_BUD_TRACING_H_ */
