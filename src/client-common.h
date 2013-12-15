#ifndef SRC_CLIENT_PRIVATE_H_
#define SRC_CLIENT_PRIVATE_H_

#include "ringbuffer.h"

#include "error.h"
#include "logger.h"


/* Forward declarations */
struct bud_client_s;

typedef enum bud_client_side_type_e bud_client_side_type_t;
typedef enum bud_client_progress_e bud_client_progress_t;
typedef struct bud_client_side_s bud_client_side_t;
typedef struct bud_client_error_s bud_client_error_t;

enum bud_client_side_type_e {
  kBudFrontend,
  kBudBackend
};

enum bud_client_progress_e {
  kBudProgressNone,
  kBudProgressRunning,
  kBudProgressDone
};

struct bud_client_side_s {
  bud_client_side_type_t type;
  uv_tcp_t tcp;
  ringbuffer input;
  ringbuffer output;

  uv_write_t write_req;
  uv_shutdown_t shutdown_req;

  bud_client_progress_t reading;
  bud_client_progress_t shutdown;
  bud_client_progress_t close;
  bud_client_progress_t write;

  size_t write_size;
};

struct bud_client_error_s {
  bud_error_t err;
  bud_client_side_t* side;
};

const char* bud_side_str(bud_client_side_type_t side);
bud_client_error_t bud_client_error(bud_error_t err, bud_client_side_t* side);
bud_client_error_t bud_client_ok();

void bud_client_close(struct bud_client_s* client, bud_client_error_t err);
void bud_client_close_cb(uv_handle_t* handle);
void bud_client_alloc_cb(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf);
void bud_client_read_cb(uv_stream_t* stream,
                        ssize_t nread,
                        const uv_buf_t* buf);
bud_client_error_t bud_client_read_start(struct bud_client_s* client,
                                         bud_client_side_t* side);
bud_client_error_t bud_client_cycle(struct bud_client_s* client);
void bud_client_log(struct bud_client_s* client,
                    bud_log_level_t level,
                    const char* fmt,
                    ...);

#define LOG(level, side, fmt, ...)                                            \
    bud_client_log(client,                                                    \
                   (level),                                                   \
                   "client %p on %s " fmt,                                    \
                   client,                                                    \
                   bud_side_str((side)->type),                                \
                   __VA_ARGS__)

#define LOG_LN(level, side, fmt)                                              \
    bud_client_log(client,                                                    \
                   (level),                                                   \
                   "client %p on %s " fmt,                                    \
                   client,                                                    \
                   bud_side_str((side)->type))

#define INFO(side, fmt, ...)                                                  \
    LOG(kBudLogInfo, side, fmt, __VA_ARGS__)

#define NOTICE(side, fmt, ...)                                                \
    LOG(kBudLogNotice, side, fmt, __VA_ARGS__)

#define WARNING(side, fmt, ...)                                               \
    LOG(kBudLogWarning, side, fmt, __VA_ARGS__)

#define DBG(side, fmt, ...)                                                   \
    LOG(kBudLogDebug, side, fmt, __VA_ARGS__)

#define WARNING_LN(side, fmt) LOG_LN(kBudLogWarning, side, fmt)
#define NOTICE_LN(side, fmt) LOG_LN(kBudLogNotice, side, fmt)
#define DBG_LN(side, fmt) LOG_LN(kBudLogDebug, side, fmt)

#endif  /* SRC_CLIENT_PRIVATE_H_ */
