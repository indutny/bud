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

typedef struct bud_context_s bud_context_t;
typedef struct bud_config_s bud_config_t;

struct bud_context_s {
  /* From config file */
  const char* servername;
  int servername_len;

  const char* cert_file;
  const char* key_file;
  const char* ciphers;
  int server_preference;
  const JSON_Array* npn;

  /* Various */
  SSL_CTX* ctx;
  char* npn_line;
  unsigned int npn_line_len;
};

struct bud_config_s {
  /* Internal, just to keep stuff allocated */
  JSON_Value* json;

  /* Just internal things */
  uv_loop_t* loop;
  int argc;
  char** argv;
  char exepath[1024];
  uv_pipe_t ipc;
  struct bud_server_s* server;
  struct bud_worker_s* workers;

  /* Options from config file */
  int worker_count;
  int restart_timeout;
  int is_daemon;
  int is_worker;

  struct {
    uint16_t port;
    const char* host;
    int proxyline;
  } frontend;

  struct {
    uint16_t port;
    const char* host;
  } backend;

  int context_count;
  bud_context_t contexts[1];
};

bud_config_t* bud_config_cli_load(int argc, char** argv, bud_error_t* err);
bud_config_t* bud_config_load(const char* path, bud_error_t* err);
void bud_config_free(bud_config_t* config);

#endif  /* SRC_CONFIG_H_ */
