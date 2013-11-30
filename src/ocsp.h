#ifndef SRC_OCSP_H_
#define SRC_OCSP_H_

#include "openssl/ssl.h"

#include "error.h"

/* Forward declaration */
struct bud_client_s;

bud_error_t bud_client_ocsp_stapling(struct bud_client_s* client);
int bud_client_stapling_cb(SSL* ssl, void* arg);

#endif  /* SRC_OCSP_H_ */
