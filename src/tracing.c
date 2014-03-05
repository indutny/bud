#include "tracing.h"
#include "client.h"

typedef struct bud_dtrace_handshake_s bud_dtrace_handshake_t;

struct bud_dtrace_handshake_s {
  int fd;
  uint16_t port;
  uint64_t host;
  uint64_t cipher;
  uint64_t protocol;
  uint64_t servername;
};

#ifdef BUD_DTRACE
# include "bud_provider.h"
# define DSTR(val) ((uint64_t) (intptr_t) (val))

void bud_trace_handshake(bud_client_t* client) {
  bud_dtrace_handshake_t h;
  int r;
  struct sockaddr_storage storage;
  int storage_size;
  struct sockaddr_in* addr;
  struct sockaddr_in6* addr6;
  char host[INET6_ADDRSTRLEN];
  char proto_st[256];

  if (!BUD_HANDSHAKE_ENABLED())
    return;

  h.fd = client->frontend.tcp.io_watcher.fd;

  storage_size = sizeof(storage);
  r = uv_tcp_getpeername(&client->frontend.tcp,
                         (struct sockaddr*) &storage,
                         &storage_size);
  if (r != 0)
    goto peername_failed;

  addr = (struct sockaddr_in*) &storage;
  addr6 = (struct sockaddr_in6*) &storage;
  if (storage.ss_family == AF_INET) {
    h.port = addr->sin_port;
    r = uv_inet_ntop(AF_INET, &addr->sin_addr, host, sizeof(host));
  } else if (storage.ss_family == AF_INET6) {
    h.port = addr6->sin6_port;
    r = uv_inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
  } else {
    r = -1;
  }

peername_failed:
  if (r != 0) {
    h.host = DSTR("<unknown>");
    h.port = 0;
  } else {
    h.host = DSTR(host);
  }

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

  BUD_HANDSHAKE(&h, h.fd, h.port, host);
}

#else  /* !BUD_DTRACE */

void bud_trace_handshake(bud_client_t* client) {
  /* no-op */
}

#endif  /* BUD_DTRACE */
