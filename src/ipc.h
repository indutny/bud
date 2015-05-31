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
typedef enum bud_ipc_ready_e bud_ipc_ready_t;
typedef struct bud_ipc_msg_header_s bud_ipc_msg_header_t;
typedef struct bud_ipc_msg_s bud_ipc_msg_t;
typedef struct bud_ipc_s bud_ipc_t;

typedef void (*bud_ipc_client_cb)(bud_ipc_t* ipc);
typedef void (*bud_ipc_msg_cb)(bud_ipc_t* ipc, bud_ipc_msg_t* msg);

enum bud_ipc_type_e {
  /* Empty message just to balance the handle */
  kBudIPCBalance = 0x0,

  /* Contents of the files used in the config, sent ahead of time */
  kBudIPCConfigFileCache = 0x1,

  /* EOF */
  kBudIPCEOF = 0x2
};

enum bud_ipc_state_e {
  kBudIPCType,
  kBudIPCHeader,
  kBudIPCBody
};

enum bud_ipc_ready_e {
  kBudIPCReadyNone,
  kBudIPCReadyNextTick,
  kBudIPCReadyDone
};

#define BUD_IPC_HEADER_SIZE 5

struct bud_ipc_msg_header_s {
  uint8_t type;
  uint32_t size;
};

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
  bud_ipc_ready_t ready;

  bud_ipc_msg_t pending;

  bud_ipc_client_cb client_cb;
  bud_ipc_msg_cb msg_cb;
};

bud_error_t bud_ipc_init(bud_ipc_t* ipc, struct bud_config_s* config);
bud_error_t bud_ipc_open(bud_ipc_t* ipc, uv_file file);
bud_error_t bud_ipc_start(bud_ipc_t* ipc);
void bud_ipc_wait(bud_ipc_t* ipc);
void bud_ipc_continue(bud_ipc_t* ipc);
bud_error_t bud_ipc_balance(bud_ipc_t* ipc, uv_stream_t* server);
bud_error_t bud_ipc_send(bud_ipc_t* ipc,
                         bud_ipc_msg_header_t* header,
                         const char* body);
uv_stream_t* bud_ipc_get_stream(bud_ipc_t* ipc);
void bud_ipc_close(bud_ipc_t* ipc);

#endif  /* SRC_IPC_H_ */
