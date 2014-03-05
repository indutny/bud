typedef struct {
  int dummy;
} bud_dtrace_handshake_t;

typedef struct {
  int dummy;
} bud_handshake_t;

provider bud {
  probe handshake(bud_dtrace_handshake_t* c,
                  int fd,
                  int port,
                  const char* host)
      : (bud_handshake_t* c, int fd, int port, const char* host);
};

#pragma D attributes Evolving/Evolving/ISA provider bud provider
#pragma D attributes Private/Private/Unknown provider bud module
#pragma D attributes Private/Private/Unknown provider bud function
#pragma D attributes Private/Private/ISA provider bud name
#pragma D attributes Evolving/Evolving/ISA provider bud args
