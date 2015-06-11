#ifndef _WIN32
# include <signal.h>  /* signal */
#endif  /* !_WIN32 */
#include <stdio.h>  /* stderr */
#include <stdlib.h>  /* NULL */
#include <string.h> /* strerror */
#include <unistd.h> /* getpid, unlink */

#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "src/config.h"
#include "src/server.h"
#include "src/master.h"
#include "src/worker.h"

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

  /* Get enough entropy to start RAND */
  for (;;) {
    int status;
    status = RAND_status();
    ASSERT(status >= 0, "RAND_status() returned negative");

    if (status != 0)
      break;

    /* Give up, RAND_poll() not supported. */
    if (RAND_poll() == 0)
      break;
  }

#ifndef _WIN32
  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);
#endif  /* !_WIN32 */

  bud_init_openssl();

  config = NULL;
  err = bud_config_new(argc, argv, &config);

  /* NOTE: bud_config_load will print everything itself */
  if (!bud_is_ok(err))
    goto fatal;

  if (config->is_worker)
    err = bud_worker(config);
  else
    err = bud_master(config);

#ifndef _WIN32
  /* Write pid file */
  if (!config->is_worker && config->pidfile != NULL) {
    pidfd = open(config->pidfile, O_WRONLY | O_CREAT, 0644);
    if (pidfd == -1) {
      fprintf(stderr, "failed to open %s: %s\n", config->pidfile, strerror(errno));
      return 1;
    }

    char pid[16];
    snprintf(pid, sizeof(pid), "%d\n", getpid());
    int n;
    do
      n = write(pidfd, pid, strlen(pid));
    while (n == -1 && errno == EINTR);

    close(pidfd);
  }
#endif  /* !_WIN32 */

  if (bud_is_ok(err))
    uv_run(config->loop, UV_RUN_DEFAULT);

  /* Finalize server */
  if (config->server != NULL) {
    bud_error_t ierr;
    if (config->is_worker)
      ierr = bud_worker_finalize(config);
    else
      ierr = bud_master_finalize(config);

    if (bud_is_ok(err) && !bud_is_ok(ierr))
      err = ierr;
  }

  if (config->loop != NULL)
    uv_run(config->loop, UV_RUN_NOWAIT);

  /* Remove pid file if applicable */
  if (pidfd > -1)
    unlink(config->pidfile);

fatal:
  if (config != NULL)
    bud_config_free(config);

  if (err.code == kBudErrSkip)
    return 0;

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
