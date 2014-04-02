#include "uv.h"

#include "xforward.h"
#include "client.h"
#include "client-common.h"
#include "config.h"
#include "logger.h"


int bud_client_xforward_done(bud_client_t* client) {
  return client->xforward.crlf == 2;
}


void bud_client_xforward_skip(bud_client_t* client, size_t size) {
  if (client->xforward.skip >= size)
    client->xforward.skip -= size;
  else
    client->xforward.skip = 0;
}


bud_client_error_t bud_client_prepend_xforward(bud_client_t* client) {
  char* out;
  size_t avail;
  size_t off;
  char xforward[256];
  int r;

  out = ringbuffer_read_next(&client->backend.output, &avail);

  /* Not enough data yet */
  if (avail <= client->xforward.skip)
    goto done;

  /* Find first CRLF */
  for (off = client->xforward.skip; off < avail; off++) {
    static char* crlf = "\r\n";
    char cur;

    cur = out[off];

    /* Reset on mismatch */
    if (cur != crlf[client->xforward.crlf]) {
      client->xforward.crlf = 0;
      continue;
    }

    /* Move forward */
    if (++client->xforward.crlf == 2) {
      off++;
      break;
    }
  }
  client->xforward.skip = off;
  if (!bud_client_xforward_done(client))
    goto done;

  /* Format header */
  r = snprintf(xforward,
               sizeof(xforward),
               "X-Forwarded-For: %s\r\n",
               client->host);

  /* Shift data and insert xforward header */
  r = ringbuffer_insert(&client->backend.output,
                        client->xforward.skip,
                        xforward,
                        (size_t) r);
  if (r != 0) {
    return bud_client_error(bud_error(kBudErrClientXForwardInsert),
                            &client->backend);
  }

done:
  return bud_client_ok(&client->backend);
}
