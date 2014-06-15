#ifndef _WIN32
# include <signal.h>  /* signal */
#endif  /* !_WIN32 */
#include <stdio.h>  /* stderr */
#include <stdlib.h>  /* NULL */
#include <string.h> /* strerror */
#include <unistd.h> /* getpid, unlink */

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
  int pidfd = -1;

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

#ifndef _WIN32
  /* Write pid file */
  if (!config->is_worker && config->pidfile != NULL) {
    pidfd = open(config->pidfile, O_WRONLY);
    if (pidfd == -1) {
      fprintf(stderr, "failed to open %s: %s\n", config->pidfile, strerror(errno));
      return 1;
    }

    char pid[16];
    snprintf(pid, sizeof(pid), "%d\n", getpid());
    int n;
    do
      n = write(pidfd, pid, sizeof(pid));
    while (n == -1 && errno == EINTR);

    close(pidfd);
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
  if (pidfd > -1)
    unlink(config->pidfile);

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
