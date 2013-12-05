#include <stdlib.h>  /* NULL */

#include "uv.h"

#include "worker.h"
#include "client.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "logger.h"

static void bud_worker_ipc_close_cb(uv_handle_t* handle);
static void bud_worker_alloc_cb(uv_handle_t* handle,
                                size_t suggested_size,
                                uv_buf_t* buf);
static void bud_worker_read_cb(uv_pipe_t* pipe,
                               ssize_t nread,
                               const uv_buf_t* buf,
                               uv_handle_type pending);

bud_error_t bud_worker(bud_config_t* config) {
  int r;
  bud_error_t err;

  bud_log(config, kBudLogDebug, "worker starting");

  config->ipc = malloc(sizeof(*config->ipc));
  if (config->ipc == NULL) {
    err = bud_error_str(kBudErrNoMem, "config->ipc");
    goto fatal;
  }

  config->ipc->data = config;
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

  r = uv_read2_start((uv_stream_t*) config->ipc,
                     bud_worker_alloc_cb,
                     bud_worker_read_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCReadStart, r);
    goto failed_pipe_open;
  }

  err = bud_ok();
  return err;

failed_pipe_open:
  uv_close((uv_handle_t*) config->ipc, bud_worker_ipc_close_cb);
  goto cleanup;

fatal:
  free(config->ipc);

cleanup:
  config->ipc = NULL;
  return err;
}


bud_error_t bud_worker_finalize(bud_config_t* config) {
  uv_close((uv_handle_t*) config->ipc, bud_worker_ipc_close_cb);
  config->ipc = NULL;

  return bud_ok();
}


void bud_worker_ipc_close_cb(uv_handle_t* handle) {
  free(handle);
}


void bud_worker_alloc_cb(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf) {
  static char tmp[128];

  *buf = uv_buf_init(tmp, sizeof(tmp));
}


void bud_worker_read_cb(uv_pipe_t* pipe,
                        ssize_t nread,
                        const uv_buf_t* buf,
                        uv_handle_type pending) {
  bud_config_t* config;

  config = pipe->data;
  ASSERT(config != NULL, "worker ipc failed to get config");
  ASSERT(nread >= 0 || nread == UV_EOF, "worker ipc read failure");

  /* Ignore reads without handles */
  if (pending == UV_UNKNOWN_HANDLE)
    return;

  ASSERT(pending == UV_TCP, "worker received non-tcp handle on ipc");
  bud_log(config, kBudLogDebug, "worker received handle");

  /* Accept client */
  bud_client_create(config, (uv_stream_t*) config->ipc);
}
