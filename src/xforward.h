#ifndef SRC_XFORWARD_H_
#define SRC_XFORWARD_H_

#include "client-common.h"

/* Forward declarations */
struct bud_client_s;

int bud_client_xforward_done(struct bud_client_s* client);
void bud_client_xforward_skip(struct bud_client_s* client, size_t size);
bud_client_error_t bud_client_prepend_xforward(struct bud_client_s* client);

#endif  /* SRC_XFORWARD_H_ */
