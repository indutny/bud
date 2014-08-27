#include <arpa/inet.h>  /* htonl */
#include <assert.h>

#include "uv.h"

#include "xforward.h"
#include "client.h"
#include "client-common.h"
#include "config.h"
#include "logger.h"
#include "openssl/ssl.h"

static const int kSpdyXForwardFrameType = 0xf000;


static bud_client_error_t bud_client_http_xforward(bud_client_t* client);
static bud_client_error_t bud_client_spdy_xforward(bud_client_t* client,
                                                   const char* protocol,
                                                   unsigned int protocol_len);


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
#ifdef OPENSSL_NPN_NEGOTIATED
  unsigned int proto_len;
  const char* protocol;

  proto_len = sizeof(protocol);
  SSL_get0_next_proto_negotiated(client->ssl,
                                 (const unsigned char**) &protocol,
                                 &proto_len);

  if (proto_len >= 5 && memcmp(protocol, "spdy/", 5) == 0) {
    return bud_client_spdy_xforward(client, protocol + 5, proto_len - 5);
  }
#endif  /* OPENSSL_NPN_NEGOTIATED */

  /* No NPN or not SPDY */
  return bud_client_http_xforward(client);
}


bud_client_error_t bud_client_http_xforward(bud_client_t* client) {
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
               "X-Forwarded-For: %.*s\r\n",
               client->remote.host_len,
               client->remote.host);

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


bud_client_error_t bud_client_spdy_xforward(bud_client_t* client,
                                            const char* protocol,
                                            unsigned int protocol_len) {
  int major;
  int minor;
  int r;
  unsigned char frame[256];

  /* Detect protocol version */
  major = -1;
  minor = 0;
  switch (protocol_len) {
    case 1:
      if (protocol[0] == '3')
        major = 3;
      else if (protocol[0] == '2')
        major = 2;
      break;
    case 3:
      if (strncmp(protocol, "3.1", protocol_len) == 0) {
        major = 3;
        minor = 1;
      }
      break;
    default:
      break;
  }

  /* We are done by now */
  client->xforward.crlf = 2;

  if (major == -1)
    goto skip;

  assert(12 + client->remote.host_len <= sizeof(frame));

  frame[0] = 0x80;
  frame[1] = major;
  *(uint16_t*) (frame + 2) = ntohs(kSpdyXForwardFrameType);

  /* Frame and Host lengths */
  *(uint32_t*) (frame + 4) = htonl(4 + client->remote.host_len);
  *(uint32_t*) (frame + 8) = htonl(client->remote.host_len);

  /* Copy hostname */
  memcpy(frame + 12, client->remote.host, client->remote.host_len);

  /* Prepend it to output data */
  r = ringbuffer_insert(&client->backend.output,
                        0,
                        (const char*) frame,
                        (size_t) 12 + client->remote.host_len);
  if (r != 0) {
    return bud_client_error(bud_error(kBudErrClientXForwardInsert),
                            &client->backend);
  }

skip:
  return bud_client_ok(&client->backend);
}
