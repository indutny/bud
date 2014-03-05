typedef struct {
  int fd;
  uint16_t port;
  uint64_t host;
  uint64_t cipher;
  uint64_t protocol;
  uint64_t servername;
} bud_dtrace_handshake_t;

typedef struct {
  int fd;
  uint16_t port;
  string host;
  string cipher;
  string protocol;
  string servername;
} bud_handshake_t;

translator bud_handshake_t <bud_dtrace_handshake_t* h> {
  fd = *(int32_t*) copyin((uintptr_t) &h->fd, sizeof(h->fd));
  port = *(uint16_t*) copyin((uintptr_t) &h->port, sizeof(h->port));
  host = copyinstr((uintptr_t) *(uint64_t*)
      copyin((uintptr_t) &h->host, sizeof(h->host)));
  cipher = copyinstr((uintptr_t) *(uint64_t*)
      copyin((uintptr_t) &h->cipher, sizeof(h->cipher)));
  protocol = copyinstr((uintptr_t) *(uint64_t*)
      copyin((uintptr_t) &h->protocol, sizeof(h->protocol)));
  servername = copyinstr((uintptr_t) *(uint64_t*)
      copyin((uintptr_t) &h->servername, sizeof(h->servername)));
};

typedef struct {
  int fd;
  uint16_t port;
  uint64_t host;
} bud_dtrace_connection_t;

typedef struct {
  int fd;
  uint16_t port;
  string host;
} bud_connection_t;

translator bud_connection_t <bud_dtrace_connection_t* c> {
  fd = *(int32_t*) copyin((uintptr_t) &c->fd, sizeof(c->fd));
  port = *(uint16_t*) copyin((uintptr_t) &c->port, sizeof(c->port));
  host = copyinstr((uintptr_t) *(uint64_t*)
      copyin((uintptr_t) &c->host, sizeof(c->host)));
};
