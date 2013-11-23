#include <stdlib.h>  /* NULL */
#include <unistd.h>  /* getopt */

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "config.h"
#include "common.h"

int main(int argc, char** argv) {
  bud_config_t* config;

  /* Initialize OpenSSL */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  config = bud_config_cli_load(argc, argv);

  /* NOTE: bud_config_load will print everything itself */
  if (config == NULL)
    return -1;

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  bud_config_free(config);

  return 0;
}
