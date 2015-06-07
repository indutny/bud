#ifndef SRC_MASTER_H_
#define SRC_MASTER_H_

#include "src/config.h"
#include "src/error.h"
#include "src/ipc.h"

/* Forward declaration */
struct bud_server_s;

typedef struct bud_worker_s bud_worker_t;
typedef bud_error_t (*bud_worker_kill_cb)(bud_worker_t* worker);

enum {
  kBudWorkerStateNone = 0x0,
  kBudWorkerStateActive = 0x1,
  kBudWorkerStateStale = 0x2,
  kBudWorkerStateDead = 0x4
};

struct bud_worker_s {
  unsigned int state;
  int index;

  bud_config_t* config;
  uv_process_t proc;
  bud_ipc_t ipc;
  uv_timer_t restart_timer;
  int close_waiting;

  bud_worker_kill_cb kill_cb;
};

bud_error_t bud_master(bud_config_t* config);
bud_error_t bud_master_finalize(bud_config_t* config);
void bud_master_balance(struct bud_server_s* server);

#endif  /* SRC_MASTER_H_ */
