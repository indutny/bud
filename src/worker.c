#include <stdlib.h>  /* NULL */

#include "uv.h"

#include "worker.h"
#include "ipc.h"
#include "client.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "logger.h"

static void bud_worker_close_cb(uv_handle_t* handle);
static void bud_worker_signal_cb(uv_signal_t* signal, int status);
static void bud_worker_ipc_client_cb(bud_ipc_t* ipc);

bud_error_t bud_worker(bud_config_t* config) {
  int r;
  bud_error_t err;

  bud_clog(config, kBudLogDebug, "worker starting");

  config->loop = uv_default_loop();
  if (config->loop == NULL) {
    err = bud_error_str(kBudErrNoMem, "config->loop");
    goto fatal;
  }

  err = bud_ipc_init(&config->ipc, config);
  if (!bud_is_ok(err))
    goto fatal;

  config->ipc.client_cb = bud_worker_ipc_client_cb;

  err = bud_ipc_open(&config->ipc, 0);
  if (!bud_is_ok(err))
    goto failed_ipc_open;

  err = bud_ipc_start(&config->ipc);
  if (!bud_is_ok(err))
    goto failed_ipc_open;

  config->signal.sighup = malloc(sizeof(*config->signal.sighup));
  if (config->signal.sighup == NULL) {
    err = bud_error_str(kBudErrNoMem, "config->.sighup");
    goto failed_ipc_open;
  }

  config->signal.sighup->data = config;

  r = uv_signal_init(config->loop, config->signal.sighup);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalInit, r);
    goto failed_signal_init;
  }

  r = uv_signal_start(config->signal.sighup, bud_worker_signal_cb, SIGHUP);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalInit, r);
    goto failed_signal_start;
  }

#ifndef _WIN32
  /* Drop privileges */
  err = bud_config_drop_privileges(config);
  if (!bud_is_ok(err))
    goto failed_signal_start;
#endif  /* !_WIN32 */

  err = bud_ok();
  return err;

failed_signal_start:
  uv_close((uv_handle_t*) config->signal.sighup, bud_worker_close_cb);
  goto failed_ipc_open;

failed_signal_init:
  free(config->signal.sighup);
  config->signal.sighup = NULL;

failed_ipc_open:
  bud_ipc_close(&config->ipc);

fatal:
  return err;
}


bud_error_t bud_worker_finalize(bud_config_t* config) {
  uv_close((uv_handle_t*) config->signal.sighup, bud_worker_close_cb);
  config->signal.sighup = NULL;
  bud_ipc_close(&config->ipc);

  return bud_ok();
}


void bud_worker_close_cb(uv_handle_t* handle) {
  free(handle);
}


void bud_worker_ipc_client_cb(bud_ipc_t* ipc) {
  /* Accept client */
  bud_client_create(ipc->config, bud_ipc_get_stream(ipc));
}


void bud_worker_signal_cb(uv_signal_t* signal, int status) {
  bud_config_t* config;

  config = signal->data;
  if (status == UV_ECANCELED)
    return;

  bud_clog(config, kBudLogInfo, "Worker shutting down");

  /* Close server and signal listener and let the worker die */
  uv_close((uv_handle_t*) config->signal.sighup, bud_worker_close_cb);
  config->signal.sighup = NULL;
  bud_ipc_close(&config->ipc);
}
