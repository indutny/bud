#ifndef SRC_CLIENT_PRIVATE_H_
#define SRC_CLIENT_PRIVATE_H_

#include "client.h"
#include "logger.h"

void bud_client_close(bud_client_t* client, bud_client_side_t* side);
void bud_client_close_cb(uv_handle_t* handle);
int bud_client_read_start(bud_client_t* client, bud_client_side_t* side);
void bud_client_cycle(bud_client_t* client);
void bud_client_log(bud_client_t* client,
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
