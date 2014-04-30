#include <stdlib.h>  /* NULL */

#include "uv.h"

#include "worker.h"
#include "client.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "logger.h"

static void bud_worker_close_cb(uv_handle_t* handle);
static void bud_worker_alloc_cb(uv_handle_t* handle,
                                size_t suggested_size,
                                uv_buf_t* buf);
static void bud_worker_read_cb(uv_stream_t* stream,
                               ssize_t nread,
                               const uv_buf_t* buf);
#ifndef _WIN32
static void bud_worker_signal_cb(uv_signal_t* signal, int status);
#endif  /* !_WIN32 */

bud_error_t bud_worker(bud_config_t* config) {
  int r;
  bud_error_t err;

  bud_log(config, kBudLogDebug, "worker starting");

  config->loop = uv_default_loop();
  config->ipc = malloc(sizeof(*config->ipc));
  config->signal.sighup = malloc(sizeof(*config->signal.sighup));
  if (config->ipc == NULL || config->signal.sighup == NULL) {
    err = bud_error_str(kBudErrNoMem, "config->ipc");
    goto fatal;
  }

  config->ipc->data = config;
  config->signal.sighup->data = config;

  r = uv_pipe_init(config->loop, config->ipc, 1);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCPipeInit, r);
    goto fatal;
  }

  r = uv_pipe_open(config->ipc, 0);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCPipeOpen, r);
    goto failed_pipe_open;
  }

  r = uv_read_start((uv_stream_t*) config->ipc,
                    bud_worker_alloc_cb,
                    bud_worker_read_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCReadStart, r);
    goto failed_pipe_open;
  }

#ifndef _WIN32
  /* Drop privileges */
  bud_config_drop_privileges(config->user, config->group);

  r = uv_signal_init(config->loop, config->signal.sighup);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalInit, r);
    goto failed_pipe_open;
  }

  r = uv_signal_start(config->signal.sighup, bud_worker_signal_cb, SIGHUP);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalInit, r);
    goto failed_signal_start;
  }
#endif  /* !_WIN32 */

  err = bud_ok();
  return err;

#ifndef _WIN32
failed_signal_start:
  uv_close((uv_handle_t*) config->signal.sighup, bud_worker_close_cb);
#endif  /* !_WIN32 */

failed_pipe_open:
  uv_close((uv_handle_t*) config->ipc, bud_worker_close_cb);
  goto cleanup;

fatal:
  free(config->ipc);

cleanup:
  config->ipc = NULL;
  return err;
}


bud_error_t bud_worker_finalize(bud_config_t* config) {
  uv_close((uv_handle_t*) config->ipc, bud_worker_close_cb);
#ifndef _WIN32
  uv_close((uv_handle_t*) config->signal.sighup, bud_worker_close_cb);
#endif  /* !_WIN32 */
  config->ipc = NULL;

  return bud_ok();
}


void bud_worker_close_cb(uv_handle_t* handle) {
  free(handle);
}


void bud_worker_alloc_cb(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf) {
  static char tmp[128];

  *buf = uv_buf_init(tmp, sizeof(tmp));
}


void bud_worker_read_cb(uv_stream_t* stream,
                        ssize_t nread,
                        const uv_buf_t* buf) {
  uv_pipe_t* pipe;
  bud_config_t* config;

  pipe = (uv_pipe_t*) stream;
  config = pipe->data;
  ASSERT(config != NULL, "worker ipc failed to get config");
  ASSERT(nread >= 0 || nread == UV_EOF, "worker ipc read failure");

  while (uv_pipe_pending_count(pipe) > 0) {
    uv_handle_type pending;

    pending = uv_pipe_pending_type(pipe);

    /* Ignore reads without handles */
    if (pending == UV_UNKNOWN_HANDLE)
      return;

    ASSERT(pending == UV_TCP, "worker received non-tcp handle on ipc");
    bud_log(config, kBudLogDebug, "worker received handle");

    /* Accept client */
    bud_client_create(config, (uv_stream_t*) config->ipc);
  }
}


#ifndef _WIN32
void bud_worker_signal_cb(uv_signal_t* signal, int status) {
  bud_config_t* config;
  bud_error_t err;

  config = signal->data;
  if (status == UV_ECANCELED)
    return;

  err = bud_config_reload(config);
  if (bud_is_ok(err))
    bud_log(config, kBudLogInfo, "Successfully reloaded config");
  else
    bud_error_log(config, kBudLogWarning, err);
}
#endif  /* !_WIN32 */
