#include <errno.h>
#include <stdio.h>  /* freopen */
#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset */
#include <unistd.h>  /* fork, setsid */

#include "uv.h"

#include "master.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "logger.h"
#include "server.h"
#include "worker.h"


#ifndef _WIN32
static int bud_daemonize(bud_error_t* err);
#endif  /* !_WIN32 */
static bud_error_t bud_master_spawn_worker(bud_worker_t* worker);
static void bud_master_kill_worker(bud_worker_t* worker,
                                   uint64_t delay,
                                   bud_worker_kill_cb cb);
static void bud_worker_timer_cb(uv_timer_t* handle, int status);
static void bud_worker_close_cb(uv_handle_t* handle);
static void bud_master_respawn_worker(uv_process_t* proc,
                                      int64_t exit_status,
                                      int term_signal);
static void bud_master_ipc_close_cb(uv_handle_t* handle);
static void bud_master_ipc_send_cb(uv_write_t* req, int status);


bud_error_t bud_master(bud_config_t* config) {
  int i;
  bud_error_t err;

  err = bud_ok();

#ifndef _WIN32
  if (config->is_daemon)
    if (bud_daemonize(&err) != 0)
      goto fatal;
#endif  /* !_WIN32 */

  /* Create server and send it to all workers */
  err = bud_server_new(config);
  if (!bud_is_ok(err))
    goto fatal;

  /* Spawn workers */
  for (i = 0; i < config->worker_count; i++) {
    config->workers[i].config = config;
    err = bud_master_spawn_worker(&config->workers[i]);

    if (!bud_is_ok(err))
      while (i-- > 0)
        bud_master_kill_worker(&config->workers[i], 0, NULL);
  }

fatal:
  return err;
}


bud_error_t bud_master_finalize(bud_config_t* config) {
  int i;

  for (i = 0; i < config->worker_count; i++)
    bud_master_kill_worker(&config->workers[i], 0, NULL);
  return bud_ok();
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
  if (chdir("/") != 0) {
    *err = bud_error_num(kBudErrChdirFailed, errno);
    return -1;
  }

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


bud_error_t bud_master_spawn_worker(bud_worker_t* worker) {
  bud_error_t err;
  bud_config_t* config;
  int i;
  int r;
  uv_process_options_t options;
  uv_buf_t buf;

  config = worker->config;
  ASSERT(config != NULL, "Worker config absent");

  memset(&options, 0, sizeof(options));
  options.exit_cb = bud_master_respawn_worker;
  options.file = config->exepath;
  options.stdio_count = 3;
  options.stdio = calloc(options.stdio_count, sizeof(*options.stdio));
  options.args = calloc(config->argc + 2, sizeof(*options.args));
  if (options.stdio == NULL || options.args == NULL) {
    err = bud_error(kBudErrNoMem);
    goto fatal;
  }

  /* args = { config.argv, "--worker" } */
  for (i = 0; i < config->argc; i++)
    options.args[i] = config->argv[i];
  options.args[i] = "--worker";
  options.args[i + 1] = NULL;

  /* stdio = { pipe, inherit, inherit } */
  options.stdio[0].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
  options.stdio[0].data.stream = (uv_stream_t*) &worker->ipc;
  options.stdio[1].flags = UV_INHERIT_FD;
  options.stdio[1].data.fd = 1;
  options.stdio[2].flags = UV_INHERIT_FD;
  options.stdio[2].data.fd = 2;

  r = uv_timer_init(config->loop, &worker->restart_timer);
  if (r != 0) {
    err = bud_error_num(kBudErrRestartTimer, r);
    goto fatal;
  }

  r = uv_pipe_init(config->loop, &worker->ipc, 1);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCPipeInit, r);
    uv_close((uv_handle_t*) &worker->restart_timer, bud_master_ipc_close_cb);
    goto fatal;
  }

  r = uv_spawn(config->loop, &worker->proc, &options);

  if (r != 0) {
    err = bud_error_num(kBudErrSpawn, r);
    uv_close((uv_handle_t*) &worker->restart_timer, bud_master_ipc_close_cb);
    uv_close((uv_handle_t*) &worker->ipc, bud_master_ipc_close_cb);
  } else {
    err = bud_ok();
    bud_log(worker->config,
            kBudLogNotice,
            "spawned bud worker<%d>",
            worker->proc.pid);
  }

  buf = uv_buf_init("ipc", 3);
  uv_write2(&worker->ipc_write,
            (uv_stream_t*) &worker->ipc,
            &buf,
            1,
            (uv_stream_t*) &config->server->tcp,
            bud_master_ipc_send_cb);

fatal:
  free(options.stdio);
  free(options.args);
  options.stdio = NULL;
  options.args = NULL;
  return err;
}


void bud_master_respawn_worker(uv_process_t* proc,
                               int64_t exit_status,
                               int term_signal) {
  bud_worker_t* worker;

  worker = container_of(proc, bud_worker_t, proc);
  ASSERT(worker != NULL, "Proc has no worker");

  bud_log(worker->config,
          kBudLogWarning,
          "bud worker<%d> died, signal: %d",
          proc->pid,
          term_signal);

  bud_master_kill_worker(worker,
                         (uint64_t) worker->config->restart_timeout,
                         bud_master_spawn_worker);
}


void bud_master_kill_worker(bud_worker_t* worker,
                            uint64_t delay,
                            bud_worker_kill_cb cb) {
  int r;

  uv_process_kill(&worker->proc, SIGKILL);
  worker->kill_cb = cb;
  worker->proc.data = worker;
  worker->ipc.data = worker;
  worker->restart_timer.data = worker;
  worker->close_waiting = 3;
  uv_close((uv_handle_t*) &worker->proc, bud_worker_close_cb);
  uv_close((uv_handle_t*) &worker->ipc, bud_worker_close_cb);
  if (delay == 0) {
    uv_close((uv_handle_t*) &worker->restart_timer, bud_worker_close_cb);
  } else {
    r = uv_timer_start(&worker->restart_timer, bud_worker_timer_cb, delay, 0);
    if (r != 0)
      uv_close((uv_handle_t*) &worker->restart_timer, bud_worker_close_cb);
  }
}


void bud_worker_timer_cb(uv_timer_t* handle, int status) {
  bud_worker_t* worker;

  worker = handle->data;
  ASSERT(worker != NULL, "Timers\'s worker absent");
  uv_close((uv_handle_t*) &worker->restart_timer, bud_worker_close_cb);
}


void bud_worker_close_cb(uv_handle_t* handle) {
  bud_worker_t* worker;

  worker = handle->data;
  ASSERT(worker != NULL, "Handle\'s worker absent");

  if (--worker->close_waiting == 0 && worker->kill_cb != NULL)
    worker->kill_cb(worker);
}


void bud_master_ipc_send_cb(uv_write_t* req, int status) {
  ASSERT(status == 0 || status == UV_ECANCELED, "Failed to send to IPC");
}


void bud_master_ipc_close_cb(uv_handle_t* handle) {
  /* No-op */
}
