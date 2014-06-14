#ifndef _WIN32
# include <signal.h>  /* signal */
#endif  /* !_WIN32 */
#include <stdio.h>  /* stderr, remove */
#include <stdlib.h>  /* NULL */
#include <string.h> /* strerror */
#include <unistd.h> /* getpid */

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

#ifdef BUD_FIPS_ENABLED
  if (!FIPS_mode_set(1)) {
    int r;
    r = ERR_get_error();
    fprintf(stderr, "openssl fips failed: %s\n", ERR_error_string(r, NULL));
    return 1;
  }
#endif  /* BUD_FIPS_ENABLED */

#ifndef _WIN32
  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);
#endif  /* !_WIN32 */

  bud_init_openssl();

  config = bud_config_cli_load(argc, argv, &err);

  /* NOTE: bud_config_load will print everything itself */
  if (config == NULL)
    goto fatal;

  if (config->is_worker)
    err = bud_worker(config);
  else
    err = bud_master(config);

  int pidfile_created = 0;
#ifndef _WIN32
  /* Write pid file */
  if (!config->is_worker && config->pidfile != NULL) {
    FILE *pidfile = fopen(config->pidfile, "w");
    if (pidfile == NULL) {
      fprintf(stderr, "failed to open %s: %s\n", config->pidfile, strerror(errno));
      return 1;
    }
    fprintf(pidfile, "%d\n", getpid());
    fclose(pidfile);
    pidfile_created = 1;
  }
#endif  /* !_WIN32 */

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

  /* Remove pid file if applicable */
  if (pidfile_created)
    remove(config->pidfile);

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
