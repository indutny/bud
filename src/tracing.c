#include "tracing.h"
#include "client.h"

typedef struct bud_dtrace_connection_s bud_dtrace_connection_t;
typedef struct bud_dtrace_handshake_s bud_dtrace_handshake_t;

#ifdef BUD_DTRACE
# include "bud_provider.h"
# define DSTR(val) ((uint64_t) (intptr_t) (val))

#define CONNECTION_FIELDS                                                     \
    int fd;                                                                   \
    uint16_t port;                                                            \
    uint64_t host;                                                            \

struct bud_dtrace_connection_s {
  CONNECTION_FIELDS
};

struct bud_dtrace_handshake_s {
  CONNECTION_FIELDS
  uint64_t cipher;
  uint64_t protocol;
  uint64_t servername;
};

#undef CONNECTION_FIELDS

static void bud_dtrace_fill_connection(bud_client_t* client,
                                       bud_dtrace_connection_t* conn) {
  conn->fd = client->frontend.tcp.io_watcher.fd;
  conn->host = DSTR(client->host);
  conn->port = client->port;
}

#else  /* !BUD_DTRACE */

/* Mock missing DTrace defines */
# define BUD_FRONTEND_ACCEPT_ENABLED() 0
# define BUD_BACKEND_CONNECT_ENABLED() 0
# define BUD_HANDSHAKE_ENABLED() 0
# define BUD_END_ENABLED() 0
# define BUD_FRONTEND_ACCEPT(a0, a1, a2, a3)
# define BUD_BACKEND_CONNECT(a0, a1, a2, a3, a4, a5, a6, a7)
# define BUD_HANDSHAKE(a0, a1, a2, a3)
# define BUD_END(a0, a1, a2, a3)

# define bud_dtrace_fill_connection(client, conn) do {} while(0)

struct bud_dtrace_connection_s {};
struct bud_dtrace_handshake_s {};

#endif  /* BUD_DTRACE */


static void bud_trace_fill_client(bud_client_t* client, bud_trace_client_t* t) {
  t->ssl = client->ssl;
  t->fd = client->frontend.tcp.io_watcher.fd;
  t->host = client->host;
  t->port = client->port;
}


static void bud_trace_invoke(bud_trace_cb_t* cbs, bud_trace_client_t* t) {
  for (; *cbs != NULL; cbs++)
    (*cbs)(t);
}


#define BUD_TRACE_INVOKE(client, name)                                        \
    do {                                                                      \
      if (client->config->trace.name != NULL) {                               \
        bud_trace_client_t t;                                                 \
        bud_trace_fill_client(client, &t);                                    \
        bud_trace_invoke(client->config->trace.name, &t) ;                    \
      }                                                                       \
    } while(0)                                                                \

#define BUD_TRACE_GENERIC(name, cname)                                        \
    void bud_trace_##name(bud_client_t* client) {                             \
      if (BUD_##cname##_ENABLED()) {                                          \
        bud_dtrace_connection_t d;                                            \
        bud_dtrace_fill_connection(client, &d);                               \
        BUD_##cname(&d, d.fd, d.port, client->host);                          \
      }                                                                       \
      BUD_TRACE_INVOKE(client, name);                                         \
    }                                                                         \

BUD_TRACE_GENERIC(frontend_accept, FRONTEND_ACCEPT)
BUD_TRACE_GENERIC(end, END)

#undef BUD_TRACE_GENERIC


void bud_trace_backend_connect(bud_client_t* client) {
  bud_dtrace_connection_t c;
  bud_dtrace_connection_t b;
  const char* bhost;

  BUD_TRACE_INVOKE(client, backend_connect);

  if (!BUD_BACKEND_CONNECT_ENABLED())
    return;

  bud_dtrace_fill_connection(client, &c);

  bhost = client->selected_backend->host;
  b.fd = client->backend.tcp.io_watcher.fd;
  b.host = DSTR(bhost);
  b.port = client->selected_backend->port;

  BUD_BACKEND_CONNECT(&c,
                      &b,
                      c.fd,
                      c.port,
                      client->host,
                      b.fd,
                      b.port,
                      (char*) bhost);
}


void bud_trace_handshake(bud_client_t* client) {
  bud_dtrace_handshake_t h;
  char proto_st[256];

  BUD_TRACE_INVOKE(client, handshake);

  if (!BUD_HANDSHAKE_ENABLED())
    return;

  bud_dtrace_fill_connection(client, (bud_dtrace_connection_t*) &h);

  h.cipher = DSTR(SSL_get_cipher_name(client->ssl));
#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  h.servername =
      DSTR(SSL_get_servername(client->ssl, TLSEXT_NAMETYPE_host_name));
#else  /* !SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */
  h.servername = 0;
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */
  if (h.servername == 0)
    h.servername = DSTR("<not available>");

#ifdef OPENSSL_NPN_NEGOTIATED
  {
    unsigned int proto_len;
    const char* protocol;

    proto_len = sizeof(protocol);
    SSL_get0_next_proto_negotiated(client->ssl,
                                   (const unsigned char**) &protocol,
                                   &proto_len);
    if (proto_len >= sizeof(proto_st))
      proto_len = sizeof(proto_st) - 1;
    memcpy(proto_st, protocol, proto_len);
    proto_st[proto_len] = '\0';
  }
  h.protocol = DSTR(proto_st);
#else  /* !OPENSSL_NPN_NEGOTIATED */
  h.protocol = DSTR("<unknown>");
#endif  /* OPENSSL_NPN_NEGOTIATED */

  BUD_HANDSHAKE(&h, h.fd, h.port, client->host);
}
