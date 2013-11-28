#ifndef SRC_HELLO_PARSER_H_
#define SRC_HELLO_PARSER_H_

#include "error.h"

typedef struct bud_client_hello_s bud_client_hello_t;

struct bud_client_hello_s {
  const char* session;
  size_t session_len;
  const char* servername;
  size_t servername_len;
  const char* ticket;
  size_t ticket_len;
};

bud_error_t bud_parse_client_hello(const char* data,
                                   size_t size,
                                   bud_client_hello_t* hello);

#endif  /* SRC_HELLO_PARSER_H_ */
