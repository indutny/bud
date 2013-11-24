#ifndef SRC_WORKER_H_
#define SRC_WORKER_H_

#include "config.h"
#include "error.h"

typedef struct bud_worker_s bud_worker_t;
typedef bud_error_t (*bud_worker_kill_cb)(bud_worker_t* worker);

struct bud_worker_s {
  bud_config_t* config;
  uv_process_t proc;
  uv_pipe_t ipc;
  uv_write_t ipc_write;
  uv_timer_t restart_timer;
  int close_waiting;

  bud_worker_kill_cb kill_cb;
};

bud_error_t bud_worker(bud_config_t* config);

#endif  /* SRC_WORKER_H_ */
