#ifndef SRC_BIO_H_
#define SRC_BIO_H_

#include "openssl/bio.h"
#include "ringbuffer.h"

BIO* bud_bio_new();
ringbuffer* bud_bio_get_buffer(BIO* bio);

#endif  /* SRC_BIO_H_ */
