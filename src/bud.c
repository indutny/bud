#include <stdlib.h>  /* fprintf */
#include <stdio.h>  /* NULL */

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "config.h"
#include "common.h"
#include "server.h"

int main(int argc, char** argv) {
  bud_config_t* config;
  bud_server_t* server;
  bud_error_t err;

  /* Initialize OpenSSL */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  config = bud_config_cli_load(argc, argv, &err);

  /* NOTE: bud_config_load will print everything itself */
  if (config == NULL)
    goto fatal;

  server = bud_server_new(uv_default_loop(), config, &err);
  if (server == NULL)
    goto fatal;

  fprintf(stdout,
          "bud is listening on %s:%d\n",
          config->frontend.host,
          config->frontend.port);
  fprintf(stdout,
          "...and routing to %s:%d\n",
          config->backend.host,
          config->backend.port);

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  bud_server_destroy(server);

  uv_run(uv_default_loop(), UV_RUN_ONCE);

  return 0;

fatal:
  if (!bud_is_ok(err)) {
    bud_error_print(stderr, err);
    return -1;
  }
  return 0;
}
