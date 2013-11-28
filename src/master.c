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
#include "client.h"

typedef struct bud_master_msg_s bud_master_msg_t;

struct bud_master_msg_s {
  bud_config_t* config;
  uv_tcp_t client;
  uv_write_t req;
};

#ifndef _WIN32
static int bud_daemonize(bud_error_t* err);
static bud_error_t bud_master_init_signals(bud_config_t* config);
static void bud_master_signal_close_cb(uv_handle_t* handle);
static void bud_master_signal_cb(uv_signal_t* handle, int signum);
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
static void bud_master_msg_close_cb(uv_handle_t* handle);
static void bud_master_msg_send_cb(uv_write_t* req, int status);


bud_error_t bud_master(bud_config_t* config) {
  int i;
  bud_error_t err;

  err = bud_ok();

  bud_log(config, kBudLogDebug, "master starting");

#ifndef _WIN32
  if (config->is_daemon)
    if (bud_daemonize(&err) != 0)
      goto fatal;

  /* Initialize signal watchers */
  err = bud_master_init_signals(config);
  if (!bud_is_ok(err))
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

  if (bud_is_ok(err)) {
    bud_log(config,
            kBudLogInfo,
            "bud listening on [%s]:%d and forwarding to [%s]:%d",
            config->frontend.host,
            config->frontend.port,
            config->backend.host,
            config->backend.port);
  }

fatal:
  return err;
}


bud_error_t bud_master_finalize(bud_config_t* config) {
  int i;

  for (i = 0; i < config->worker_count; i++)
    if (config->workers[i].active)
      bud_master_kill_worker(&config->workers[i], 0, NULL);

#ifndef _WIN32
  uv_close((uv_handle_t*) &config->signal.sigterm, bud_master_signal_close_cb);
  uv_close((uv_handle_t*) &config->signal.sigint, bud_master_signal_close_cb);
#endif  /* !_WIN32 */

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


bud_error_t bud_master_init_signals(bud_config_t* config) {
  int r;
  bud_error_t err;

  config->signal.sigterm.data = config;
  config->signal.sigint.data = config;

  r = uv_signal_init(config->loop, &config->signal.sigterm);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalInit, r);
    goto fatal;
  }
  r = uv_signal_init(config->loop, &config->signal.sigint);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalInit, r);
    goto failed_sigint_init;
  }

  r = uv_signal_start(&config->signal.sigterm, bud_master_signal_cb, SIGTERM);
  if (r == 0)
    r = uv_signal_start(&config->signal.sigint, bud_master_signal_cb, SIGINT);
  if (r != 0) {
    err = bud_error_num(kBudErrSignalStart, r);
    goto failed_sigint_init;
  }

  return bud_ok();

failed_sigint_init:
  uv_close((uv_handle_t*) &config->signal.sigterm, bud_master_signal_close_cb);

fatal:
  return err;
}


void bud_master_signal_close_cb(uv_handle_t* handle) {
  /* No-op */
}


void bud_master_signal_cb(uv_signal_t* handle, int signum) {
  /* Stop the loop and let finalize to be called */
  uv_stop(handle->loop);
}
#endif  /* !_WIN32 */


bud_error_t bud_master_spawn_worker(bud_worker_t* worker) {
  bud_error_t err;
  bud_config_t* config;
  int i;
  int r;
  uv_process_options_t options;

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
    worker->active = 1;
    err = bud_ok();
    bud_log(worker->config,
            kBudLogInfo,
            "spawned bud worker<%d>",
            worker->proc.pid);

    /* Pending accept - try balancing */
    if (config->pending_accept) {
      config->pending_accept = 0;
      bud_master_balance(config->server);
    }
  }

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
  ASSERT(worker->active, "Tried to kill inactive worker");

  uv_process_kill(&worker->proc, SIGKILL);
  worker->active = 0;
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


void bud_master_ipc_close_cb(uv_handle_t* handle) {
  /* No-op */
}


void bud_master_balance(struct bud_server_s* server) {
  int r;
  bud_config_t* config;
  bud_worker_t* worker;
  int last_index;
  bud_master_msg_t* msg;
  uv_buf_t buf;

  config = server->config;

  if (config->worker_count == 0) {
    bud_log(config, kBudLogDebug, "master self accept");

    /* Master = worker */
    return bud_client_create(config, (uv_stream_t*) &server->tcp);
  }

  bud_log(config,
          kBudLogDebug,
          "master balance");

  /* Round-robin worker selection */
  last_index = (config->last_worker + 1) % config->worker_count;
  do {
    config->last_worker++;
    config->last_worker %= config->worker_count;
    worker = &config->workers[config->last_worker];
  } while (!worker->active && config->last_worker != last_index);

  /* All workers are down... wait */
  if (!worker->active) {
    config->pending_accept = 1;
    return;
  }

  msg = malloc(sizeof(*msg));
  if (msg == NULL) {
    bud_error_log(config,
                  kBudLogWarning,
                  bud_error_str(kBudErrNoMem, "bud_master_msg_t"));
    return;
  }
  msg->config = config;

  /* Accept handle */
  r = uv_tcp_init(config->loop, &msg->client);
  if (r != 0) {
    bud_log(config,
            kBudLogWarning,
            "master uv_tcp_init() failed with (%d) \"%s\"",
            r,
            uv_strerror(r));
    goto failed_tcp_init;
  }

  r = uv_accept((uv_stream_t*) &server->tcp, (uv_stream_t*) &msg->client);
  if (r != 0) {
    bud_log(config,
            kBudLogWarning,
            "master uv_accept() failed with (%d) \"%s\"",
            r,
            uv_strerror(r));
    goto failed_accept;
  }

  buf = uv_buf_init("x", 1);

  r = uv_write2(&msg->req,
                (uv_stream_t*) &worker->ipc,
                &buf,
                1,
                (uv_stream_t*) &msg->client,
                bud_master_msg_send_cb);
  if (r != 0) {
    bud_log(config,
            kBudLogWarning,
            "master uv_write2() failed with (%d) \"%s\"",
            r,
            uv_strerror(r));
    goto failed_accept;
  }
  return;

failed_accept:
  uv_close((uv_handle_t*) &msg->client, bud_master_msg_close_cb);

failed_tcp_init:
  free(msg);
}


void bud_master_msg_close_cb(uv_handle_t* handle) {
  bud_master_msg_t* msg;

  msg = container_of(handle, bud_master_msg_t, client);
  free(msg);
}


void bud_master_msg_send_cb(uv_write_t* req, int status) {
  bud_master_msg_t* msg;

  if (status == UV_ECANCELED)
    return;

  msg = container_of(req, bud_master_msg_t, req);
  if (status != 0) {
    bud_log(msg->config,
            kBudLogWarning,
            "master write_cb() failed with (%d) \"%s\"",
            status,
            uv_strerror(status));
  }

  uv_close((uv_handle_t*) &msg->client, bud_master_msg_close_cb);
}
