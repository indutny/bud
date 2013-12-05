#include <stdio.h>  /* stderr */
#include <stdlib.h>  /* NULL */

#include "openssl/ssl.h"
#include "openssl/err.h"

#include "config.h"
#include "server.h"
#include "master.h"
#include "worker.h"

static void bud_init_openssl();


int main(int argc, char** argv) {
  bud_config_t* config;
  bud_error_t err;

  bud_init_openssl();

  config = bud_config_cli_load(uv_default_loop(), argc, argv, &err);

  /* NOTE: bud_config_load will print everything itself */
  if (config == NULL)
    goto fatal;

  if (config->is_worker)
    err = bud_worker(config);
  else
    err = bud_master(config);

  if (bud_is_ok(err))
    uv_run(config->loop, UV_RUN_DEFAULT);

  /* Finalize server */
  if (config->server != NULL) {
    if (config->is_worker)
      err = bud_worker_finalize(config);
    else
      err = bud_master_finalize(config);
  }

  uv_run(config->loop, UV_RUN_NOWAIT);

fatal:
  if (config != NULL)
    bud_config_free(config);

  if (!bud_is_ok(err)) {
    bud_error_print(stderr, err);
    return -1;
  }
  return 0;
}


void bud_init_openssl() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  SSL_load_error_strings();
  ERR_load_crypto_strings();
}
