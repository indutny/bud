#ifndef SRC_CONFIG_TICKET_H_
#define SRC_CONFIG_TICKET_H_

#include "src/config.h"
#include "src/common.h"

bud_error_t bud_context_set_ticket(bud_context_t* context,
                                   const char* ticket,
                                   size_t size,
                                   bud_encoding_t enc);
void bud_context_rotate_cb(uv_timer_t* timer);

#endif  /* SRC_CONFIG_TICKET_H_ */
