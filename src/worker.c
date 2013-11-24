#include <stdio.h>  /* fprintf */
#include <stdlib.h>  /* NULL */
#include <unistd.h>  /* getpid */

#include "uv.h"

#include "worker.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "server.h"

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

  /* Create server */
  err = bud_server_new(config);
  if (!bud_is_ok(err))
    goto fatal;

  fprintf(stdout,
          "[%d] bud is listening on [%s]:%d ...and routing to [%s]:%d\n",
#ifndef _WIN32
          getpid(),
#else
          0,
#endif  /* !_WIN32 */
          config->frontend.host,
          config->frontend.port,
          config->backend.host,
          config->backend.port);

  fatal:
    if (!bud_is_ok(err)) {
      bud_error_print(stderr, err);
      ASSERT(0, "Unrecoverable failure");
    }
}
