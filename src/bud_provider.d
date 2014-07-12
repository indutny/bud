typedef struct {
  int dummy;
} bud_dtrace_handshake_t;

typedef struct {
  int dummy;
} bud_handshake_t;

typedef struct {
  int dummy;
} bud_dtrace_connection_t;

typedef struct {
  int dummy;
} bud_connection_t;

provider bud {
  probe frontend_accept(bud_dtrace_connection_t* c,
                        int fd,
                        int port,
                        const char* host)
      : (bud_connection_t* c, int fd, int port, const char* host);

  probe backend_connect(bud_dtrace_connection_t* c,
                        bud_dtrace_connection_t* backend,
                        int fd,
                        int port,
                        const char* host,
                        int backend_fd,
                        int backend_port,
                        const char* backend_host)
      : (bud_connection_t* c,
         bud_connection_t* backend,
         int fd,
         int port,
         const char* host,
         int backend_fd,
         int backend_port,
         const char* backend_host);

  probe kill_backend(bud_dtrace_connection_t* c,
                     bud_dtrace_connection_t* backend,
                     int fd,
                     int port,
                     const char* host,
                     int backend_port,
                     const char* backend_host)
      : (bud_connection_t* c,
         bud_connection_t* backend,
         int fd,
         int port,
         const char* host,
         int backend_port,
         const char* backend_host);

  probe revive_backend(bud_dtrace_connection_t* c,
                       bud_dtrace_connection_t* backend,
                       int fd,
                       int port,
                       const char* host,
                       int backend_port,
                       const char* backend_host)
      : (bud_connection_t* c,
         bud_connection_t* backend,
         int fd,
         int port,
         const char* host,
         int backend_port,
         const char* backend_host);

  probe end(bud_dtrace_connection_t* c,
            int fd,
            int port,
            const char* host)
      : (bud_connection_t* c, int fd, int port, const char* host);

  probe retry(bud_dtrace_connection_t* c,
              int fd,
              int port,
              const char* host)
      : (bud_connection_t* c, int fd, int port, const char* host);

  probe handshake(bud_dtrace_handshake_t* c,
                  int fd,
                  int port,
                  const char* host)
      : (bud_handshake_t* c, int fd, int port, const char* host);

  probe error(bud_dtrace_connection_t* c,
              int fd,
              int port,
              const char* host,
              int code)
      : (bud_connection_t* c, int fd, int port, const char* host, int code);
};

#pragma D attributes Evolving/Evolving/ISA provider bud provider
#pragma D attributes Private/Private/Unknown provider bud module
#pragma D attributes Private/Private/Unknown provider bud function
#pragma D attributes Private/Private/ISA provider bud name
#pragma D attributes Evolving/Evolving/ISA provider bud args
