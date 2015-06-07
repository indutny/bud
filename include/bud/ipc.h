#ifndef INCLUDE_BUD_IPC_H_
#define INCLUDE_BUD_IPC_H_

typedef enum bud_ipc_type_e bud_ipc_type_t;
typedef struct bud_ipc_msg_header_s bud_ipc_msg_header_t;
typedef struct bud_ipc_msg_s bud_ipc_msg_t;

enum bud_ipc_type_e {
  /* Empty message just to balance the handle (internal) */
  kBudIPCBalance = 0x0,

  /* Contents of the files used in the config, sent ahead of time (internal) */
  kBudIPCConfigFileCache = 0x1,

  /* EOF (internal) */
  kBudIPCEOF = 0x2,

  /* Set TLS Ticket */
  /* Message data format: [4-byte BE context index] [48-byte key] */
  kBudIPCSetTicket = 0x3
};

struct bud_ipc_msg_header_s {
  uint8_t type;
  uint32_t size;
};

struct bud_ipc_msg_s {
  uint8_t type;
  uint32_t size;
  char data[1];
};

#endif  /* INCLUDE_BUD_IPC_H_ */
