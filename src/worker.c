#include <stdlib.h>  /* NULL */

#include "uv.h"

#include "worker.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "logger.h"
#include "server.h"

static void bud_worker_alloc_cb(uv_handle_t* handle,
                                size_t suggested_size,
                                uv_buf_t* buf);
static void bud_worker_read_cb(uv_pipe_t* pipe,
                               ssize_t nread,
                               const uv_buf_t* buf,
                               uv_handle_type pending);
static bud_error_t bud_worker_create_server(bud_config_t* config);

bud_error_t bud_worker(bud_config_t* config) {
  int r;
  bud_error_t err;

  /* Worker = master */
  if (config->worker_count == 0)
    return bud_worker_create_server(config);

  r = uv_pipe_init(config->loop, &config->ipc, 1);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCPipeInit, r);
    goto fatal;
  }

  r = uv_pipe_open(&config->ipc, 0);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCPipeOpen, r);
    goto fatal;
  }

  r = uv_read2_start((uv_stream_t*) &config->ipc,
                     bud_worker_alloc_cb,
                     bud_worker_read_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCReadStart, r);
    goto fatal;
  }

  err = bud_ok();

fatal:
  return err;
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
  bud_error_t err;
  bud_config_t* config;

  config = container_of(pipe, bud_config_t, ipc);
  ASSERT(config != NULL, "worker ipc failed to get config");
  ASSERT(nread >= 0 || nread == UV_EOF, "worker ipc read failure");

  /* Ignore reads without handles */
  if (pending == UV_UNKNOWN_HANDLE)
    return;

  ASSERT(0 == uv_read_stop((uv_stream_t*) pipe), "worker failed to stop ipc");
  ASSERT(pending == UV_TCP, "worker received non-tcp handle on ipc");

  err = bud_worker_create_server(config);

  if (!bud_is_ok(err)) {
    bud_error_log(config, kBudLogFatal, err);
    ASSERT(0, "Unrecoverable failure");
  }
}


bud_error_t bud_worker_create_server(bud_config_t* config) {
  bud_error_t err;

  /* Create server */
  err = bud_server_new(config);
  if (!bud_is_ok(err))
    return err;

  bud_log(config,
          kBudLogInfo,
          "bud is listening on [%s]:%d ...and routing to [%s]:%d",
          config->frontend.host,
          config->frontend.port,
          config->backend.host,
          config->backend.port);

  return bud_ok();
}
