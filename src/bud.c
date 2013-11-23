#include <errno.h>  /* errno */
#include <stdlib.h>  /* fprintf */
#include <stdio.h>  /* NULL */
#include <unistd.h>  /* fork, setsid */

#include "uv.h"
#include "ringbuffer.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "config.h"
#include "common.h"
#include "server.h"

#ifndef _WIN32
static int bud_daemonize(bud_error_t* err);
#endif  /* !_WIN32 */


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

#ifndef _WIN32
  if (config->is_daemon)
    if (bud_daemonize(&err) != 0)
      goto fatal;
#endif  /* !_WIN32 */

  server = bud_server_new(uv_default_loop(), config, &err);
  if (server == NULL)
    goto fatal;

  fprintf(stdout,
          "bud is listening on [%s]:%d\n",
          config->frontend.host,
          config->frontend.port);
  fprintf(stdout,
          "...and routing to [%s]:%d\n",
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


#ifndef _WIN32
int bud_daemonize(bud_error_t* err) {
  pid_t p;

  p = fork();
  if (p > 0) {
    *err = bud_ok();

    /* Make parent exit */
    return -1;
  } else if (p == -1) {
    *err = bud_error_num(kBudErrForkFailed, errno);
    return -1;
  }

  /* Child starts new life here */
  p = setsid();
  if (p == -1) {
    *err = bud_error_num(kBudErrSetsidFailed, errno);
    return -1;
  }

  freopen("/dev/null", "r", stdin);
  freopen("/dev/null", "w", stdout);
  freopen("/dev/null", "w", stderr);
  if (stdin == NULL || stdout == NULL || stderr == NULL) {
    *err = bud_error(kBudErrNoMem);
    return -1;
  }

  return 0;
}
#endif  /* !_WIN32 */
