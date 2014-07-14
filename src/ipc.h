#ifndef SRC_IPC_H_
#define SRC_IPC_H_

#include <stdint.h>

#include "uv.h"

#include "error.h"
#include "ringbuffer.h"

/* Forward declarations */
struct bud_config_s;

typedef enum bud_ipc_type_e bud_ipc_type_t;
typedef enum bud_ipc_state_e bud_ipc_state_t;
typedef struct bud_ipc_msg_s bud_ipc_msg_t;
typedef struct bud_ipc_s bud_ipc_t;

typedef void (*bud_ipc_client_cb)(bud_ipc_t* ipc);

enum bud_ipc_type_e {
  /* Empty message just to balance the handle */
  kBudIPCBalance = 0x0,

  /* Contents of the files used in the config, sent ahead of time */
  kBudIPCConfigFile = 0x1,

  /* Config JSON string */
  kBudIPCConfig = 0x2
};

enum bud_ipc_state_e {
  kBudIPCType,
  kBudIPCHeader,
  kBudIPCBody
};

#define BUD_IPC_HEADER_SIZE 5

struct bud_ipc_msg_s {
  uint8_t type;
  uint32_t size;
  char data[1];
};

struct bud_ipc_s {
  struct bud_config_s* config;
  uv_pipe_t* handle;

  ringbuffer buffer;
  bud_ipc_state_t state;
  size_t waiting;

  bud_ipc_client_cb client_cb;
};

bud_error_t bud_ipc_init(bud_ipc_t* ipc, struct bud_config_s* config);
bud_error_t bud_ipc_open(bud_ipc_t* ipc, uv_file file);
bud_error_t bud_ipc_start(bud_ipc_t* ipc);
bud_error_t bud_ipc_balance(bud_ipc_t* ipc, uv_stream_t* server);
uv_stream_t* bud_ipc_get_stream(bud_ipc_t* ipc);
void bud_ipc_close(bud_ipc_t* ipc);

#endif  /* SRC_IPC_H_ */
