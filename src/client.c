#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>

#include "uv.h"
#include "bio.h"
#include "ringbuffer.h"
#include "openssl/bio.h"

#include "common.h"
#include "client.h"
#include "hello-parser.h"
#include "logger.h"
#include "redis.h"

static void bud_client_side_init(bud_client_side_t* side,
                                 bud_client_side_type_t type,
                                 bud_client_t* client);
static void bud_client_side_destroy(bud_client_side_t* side);
static bud_client_side_t* bud_client_side_by_tcp(bud_client_t* client,
                                                 uv_tcp_t* tcp);
static void bud_client_close(bud_client_t* client, bud_client_side_t* side);
static void bud_client_close_cb(uv_handle_t* handle);
static void bud_client_alloc_cb(uv_handle_t* handle,
                                size_t suggested_size,
                                uv_buf_t* buf);
static void bud_client_read_cb(uv_stream_t* stream,
                               ssize_t nread,
                               const uv_buf_t* buf);
static void bud_client_cycle(bud_client_t* client);
static void bud_client_parse_hello(bud_client_t* client);
static void bud_client_sni_cb(bud_redis_sni_t* req, bud_error_t err);
static void bud_client_backend_in(bud_client_t* client);
static void bud_client_backend_out(bud_client_t* client);
static int bud_client_throttle(bud_client_t* client,
                               bud_client_side_t* side,
                               ringbuffer* buf);
static void bud_client_send(bud_client_t* client, bud_client_side_t* side);
static void bud_client_send_cb(uv_write_t* req, int status);
static void bud_client_connect_cb(uv_connect_t* req, int status);
static void bud_client_shutdown(bud_client_t* client, bud_client_side_t* side);
static void bud_client_shutdown_cb(uv_shutdown_t* req, int status);
static int bud_client_prepend_proxyline(bud_client_t* client);
static void bud_client_log(bud_client_t* client,
                           bud_client_side_t* side,
                           const char* fmt,
                           int code,
                           const char* reason);
static void bud_client_debug(bud_client_t* client,
                             bud_client_side_t* side,
                             const char* fmt,
                             int code);
static const char* bud_sslerror_str(int err);
static const char* bud_side_str(bud_client_side_type_t side);


void bud_client_create(bud_config_t* config, uv_stream_t* stream) {
  int r;
  bud_client_t* client;
  BIO* enc_in;
  BIO* enc_out;
#ifdef SSL_MODE_RELEASE_BUFFERS
  long mode;
#endif  /* SSL_MODE_RELEASE_BUFFERS */

  client = malloc(sizeof(*client));
  if (client == NULL)
    return;

  client->config = config;
  client->ssl = NULL;
  client->close = kBudProgressNone;
  client->hello_parse = config->redis.enabled ? kBudProgressRunning :
                                                kBudProgressDone;
  client->sni_req = NULL;
  client->destroy_waiting = 0;

  /* Initialize buffers */
  bud_client_side_init(&client->frontend, kBudFrontend, client);
  bud_client_side_init(&client->backend, kBudBackend, client);

  /**
   * Accept client on frontend
   */
  r = uv_tcp_init(config->loop, &client->frontend.tcp);
  if (r != 0)
    goto failed_tcp_in_init;

  r = uv_accept(stream, (uv_stream_t*) &client->frontend.tcp);
  if (r != 0)
    goto failed_accept;

  r = uv_read_start((uv_stream_t*) &client->frontend.tcp,
                    bud_client_alloc_cb,
                    bud_client_read_cb);
  if (r != 0)
    goto failed_accept;
  client->frontend.reading = kBudProgressRunning;

  /*
   * Connect to backend
   * NOTE: We won't start reading until some SSL data will be sent.
   */
  r = uv_tcp_init(config->loop, &client->backend.tcp);
  if (r != 0)
    goto failed_accept;

  r = uv_tcp_connect(&client->connect_req,
                     &client->backend.tcp,
                     (struct sockaddr*) &client->config->backend.addr,
                     bud_client_connect_cb);
  if (r != 0)
    goto failed_connect;

  /* Adjust sockets */
  r = uv_tcp_nodelay(&client->frontend.tcp, 1);
  if (r == 0)
    r = uv_tcp_nodelay(&client->backend.tcp, 1);
  if (r == 0 && config->frontend.keepalive > 0)
    r = uv_tcp_keepalive(&client->frontend.tcp, 1, config->frontend.keepalive);
  if (r == 0 && config->backend.keepalive > 0)
    r = uv_tcp_keepalive(&client->backend.tcp, 1, config->backend.keepalive);
  if (r != 0)
    goto failed_connect;

  /* Initialize SSL */

  /* First context is always default */
  client->ssl = SSL_new(config->contexts[0].ctx);
  if (client->ssl == NULL)
    goto failed_connect;

  enc_in = bud_bio_new(&client->frontend.input);
  if (enc_in == NULL)
    goto failed_connect;
  enc_out = bud_bio_new(&client->frontend.output);
  if (enc_out == NULL) {
    BIO_free_all(enc_in);
    goto failed_connect;
  }
  SSL_set_bio(client->ssl, enc_in, enc_out);

#ifdef SSL_MODE_RELEASE_BUFFERS
  mode = SSL_get_mode(client->ssl);
  SSL_set_mode(client->ssl, mode | SSL_MODE_RELEASE_BUFFERS);
#endif  /* SSL_MODE_RELEASE_BUFFERS */

  SSL_set_accept_state(client->ssl);

  if (config->frontend.proxyline) {
    r = bud_client_prepend_proxyline(client);
    if (r != 0)
      goto failed_connect;
  }

  client->destroy_waiting = 2;
  bud_client_debug(client,
                   &client->frontend,
                   "client %p new (%d) %s",
                   0);
  return;

failed_connect:
  client->destroy_waiting++;
  uv_close((uv_handle_t*) &client->backend.tcp, bud_client_close_cb);

failed_accept:
  client->destroy_waiting++;
  uv_close((uv_handle_t*) &client->frontend.tcp, bud_client_close_cb);
  return;

failed_tcp_in_init:
  free(client);
}


void bud_client_side_init(bud_client_side_t* side,
                          bud_client_side_type_t type,
                          bud_client_t* client) {
  side->type = type;
  side->tcp.data = client;
  ringbuffer_init(&side->input);
  ringbuffer_init(&side->output);
  side->reading = kBudProgressNone;
  side->shutdown = kBudProgressNone;
  side->close = kBudProgressNone;
  side->write = kBudProgressNone;
  side->write_size = 0;
}


void bud_client_side_destroy(bud_client_side_t* side) {
  ringbuffer_destroy(&side->input);
  ringbuffer_destroy(&side->output);
}


bud_client_side_t* bud_client_side_by_tcp(bud_client_t* client, uv_tcp_t* tcp) {
  if (tcp == &client->frontend.tcp)
    return &client->frontend;
  else
    return &client->backend;
}


void bud_client_close(bud_client_t* client, bud_client_side_t* side) {
  if (client->close == kBudProgressRunning) {
    /* Force close, even if waiting */
    if (side->close == kBudProgressRunning) {
      bud_client_debug(client,
                       side,
                       "client %p force closing (%d) %s",
                       0);
      uv_close((uv_handle_t*) &side->tcp, bud_client_close_cb);
      side->close = kBudProgressDone;
      client->close = kBudProgressDone;
    }
    return;
  } else if (client->close == kBudProgressDone) {
    return;
  }

  /* Close offending side, and wait for write finish on other side */
  client->close = kBudProgressRunning;

  if (side->type == kBudBackend &&
      !ringbuffer_is_empty(&client->frontend.output)) {
    client->frontend.close = kBudProgressRunning;
  } else {
    bud_client_debug(client,
                     &client->frontend,
                     "client %p force closing (%d) %s (and waiting for other)",
                     0);
    uv_close((uv_handle_t*) &client->frontend.tcp, bud_client_close_cb);
    client->frontend.close = kBudProgressDone;
  }

  if (side->type == kBudFrontend &&
      !ringbuffer_is_empty(&client->backend.output)) {
    client->backend.close = kBudProgressRunning;
  } else {
    bud_client_debug(client,
                     &client->backend,
                     "client %p force closing (%d) %s (and waiting for other)",
                     0);
    uv_close((uv_handle_t*) &client->backend.tcp, bud_client_close_cb);
    client->backend.close = kBudProgressDone;
  }
}


void bud_client_close_cb(uv_handle_t* handle) {
  bud_client_t* client;

  client = (bud_client_t*) handle->data;

  if (--client->destroy_waiting != 0)
    return;

  bud_client_side_destroy(&client->frontend);
  bud_client_side_destroy(&client->backend);

  if (client->ssl != NULL)
    SSL_free(client->ssl);
  client->ssl = NULL;
  if (client->sni_req != NULL)
    bud_redis_sni_close(client->config->redis.ctx, client->sni_req);
  client->sni_req = NULL;
  free(client);
}


void bud_client_alloc_cb(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf) {
  bud_client_t* client;
  bud_client_side_t* side;
  size_t avail;
  char* ptr;

  client = handle->data;
  side = bud_client_side_by_tcp(client, (uv_tcp_t*) handle);

  avail = 0;
  ptr = ringbuffer_write_ptr(&side->input, &avail);
  *buf = uv_buf_init(ptr, avail);
}


void bud_client_read_cb(uv_stream_t* stream,
                        ssize_t nread,
                        const uv_buf_t* buf) {
  int r;
  bud_client_t* client;
  bud_client_side_t* side;
  bud_client_side_t* opposite;

  client = stream->data;
  side = bud_client_side_by_tcp(client, (uv_tcp_t*) stream);

  /* Commit data if there was no error */
  r = 0;
  if (nread >= 0)
    r = ringbuffer_write_append(&side->input, nread);

  bud_client_debug(client,
                   side,
                   "client %p after read_cb() => %d on %s",
                   nread);

  /* Handle EOF */
  if (nread == UV_EOF) {
    side->reading = kBudProgressDone;

    /* Shutdown opposite side */
    opposite = side == &client->frontend ? &client->backend : &client->frontend;
    bud_client_shutdown(client, opposite);
  }

  /* Try writing out data anyway */
  bud_client_cycle(client);

  if ((r != 0 || nread < 0) && nread != UV_EOF) {
    if (nread < 0) {
      bud_client_log(client,
                     side,
                     "client %p read_cb failed with (%d) \"%s\" on %s",
                     nread,
                     uv_strerror(nread));
    } else {
      bud_client_log(client,
                     side,
                     "client %p write_append failed with (%d) \"%s\" on %s",
                     r,
                     NULL);
    }

    /* Unrecoverable socket error, close */
    return bud_client_close(client, side);
  }

  /* If buffer is full - stop reading */
  if (bud_client_throttle(client, side, &side->input) == -1)
    return bud_client_close(client, side);
}


void bud_client_cycle(bud_client_t* client) {
  /* Parsing, must wait */
  if (client->hello_parse != kBudProgressDone) {
    bud_client_parse_hello(client);
  } else {
    bud_client_backend_in(client);
    bud_client_backend_out(client);
    bud_client_send(client, &client->frontend);
    bud_client_send(client, &client->backend);
  }
}


void bud_client_parse_hello(bud_client_t* client) {
  bud_error_t err;
  char* data;
  size_t size;

  if (ringbuffer_is_empty(&client->frontend.input))
    return;

  data = ringbuffer_read_next(&client->frontend.input, &size);
  err = bud_parse_client_hello(data, (size_t) size, &client->hello);
  if (err.code == kBudErrParserNeedMore)
    return;

  if (!bud_is_ok(err)) {
    bud_client_log(client,
                   &client->frontend,
                   "client %p failed to parse hello with (%d) \"%s\" on %s",
                   err.code,
                   err.str);
    bud_client_close(client, &client->frontend);
    return;
  }

  /* No servername was given */
  if (client->hello.servername_len == 0) {
    client->hello_parse = kBudProgressDone;
    bud_client_cycle(client);
    return;
  }

  /* Parse success, perform redis lookup */
  client->sni_req = bud_redis_sni(client->config->redis.ctx,
                                  client->hello.servername,
                                  client->hello.servername_len,
                                  bud_client_sni_cb,
                                  client,
                                  &err);
  if (!bud_is_ok(err)) {
    bud_client_log(client,
                   &client->frontend,
                   "client %p failed to request SNI with (%d) \"%s\" on %s",
                   err.code,
                   err.str);
    bud_client_close(client, &client->frontend);
  }
}


void bud_client_sni_cb(bud_redis_sni_t* req, bud_error_t err) {
  bud_client_t* client;

  client = req->data;
  client->sni_req = NULL;
  if (!bud_is_ok(err)) {
    bud_client_log(client,
                   &client->frontend,
                   "client %p SNI cb failed with (%d) \"%s\" on %s",
                   err.code,
                   err.str);
    bud_client_close(client, &client->frontend);
    return;
  }

  /* Success */
  if (req->sni == NULL) {
    /* Not found */
    /* TODO(indunty): log servername*/
    bud_client_log(client,
                   &client->frontend,
                   "client %p SNI name not found (%d) \"%s\" on %s",
                   0,
                   NULL);
  } else {
    bud_client_log(client,
                   &client->frontend,
                   "client %p SNI name found (%d) \"%s\" on %s",
                   0,
                   NULL);
    SSL_set_app_data(client->ssl, req->sni);
  }
  client->hello_parse = kBudProgressDone;
  bud_client_cycle(client);
}


void bud_client_backend_in(bud_client_t* client) {
  char* data;
  size_t size;
  int written;
  int err;

  written = 0;
  while (!ringbuffer_is_empty(&client->backend.input)) {
    data = ringbuffer_read_next(&client->backend.input, &size);
    written = SSL_write(client->ssl, data, size);
    bud_client_debug(client,
                     &client->frontend,
                     "client %p SSL_write() => %d on %s",
                     written);
    bud_client_debug(client,
                     &client->frontend,
                     "client %p frontend.output => (%d) on %s",
                     ringbuffer_size(&client->frontend.output));
    if (written < 0)
      break;

    ASSERT(written == (int) size, "SSL_write() did unexpected partial write");
    ringbuffer_read_skip(&client->backend.input, written);
  }

  if (bud_client_throttle(client,
                          &client->frontend,
                          &client->frontend.output) == -1) {
    /* Throttle error */
    bud_client_close(client, &client->frontend);
    return;
  }

  if (written >= 0)
    return;

  err = SSL_get_error(client->ssl, written);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return;

  bud_client_log(client,
                 &client->frontend,
                 "client %p SSL_write failed with (%d) \"%s\" on %s",
                 err,
                 bud_sslerror_str(err));
  bud_client_close(client, &client->frontend);
}


void bud_client_backend_out(bud_client_t* client) {
  int read;
  int err;
  size_t avail;
  char* out;

  /* If buffer is full - stop reading */
  err = bud_client_throttle(client,
                            &client->backend,
                            &client->backend.output);
  if (err < 0)
    return bud_client_close(client, &client->backend);
  else if (err == 1)
    return;

  do {
    avail = 0;
    out = ringbuffer_write_ptr(&client->backend.output, &avail);
    read = SSL_read(client->ssl, out, avail);
    bud_client_debug(client,
                     &client->frontend,
                     "client %p SSL_read() => %d on %s",
                     read);
    if (read > 0) {
      ringbuffer_write_append(&client->backend.output, read);
      bud_client_send(client, &client->backend);
    }
  } while (read > 0);

  if (read > 0)
    return;

  err = SSL_get_error(client->ssl, read);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return;

  if (err != SSL_ERROR_ZERO_RETURN) {
    bud_client_log(client,
                   &client->frontend,
                   "client %p SSL_read failed with (%d) \"%s\" on %s",
                   err,
                   bud_sslerror_str(err));
  }
  bud_client_close(client, &client->frontend);
}


int bud_client_throttle(bud_client_t* client,
                        bud_client_side_t* side,
                        ringbuffer* buf) {
  int err;
  bud_client_side_t* opposite;

  if (ringbuffer_is_full(buf)) {
    opposite = side == &client->frontend ? &client->backend : &client->frontend;
    if (opposite->reading != kBudProgressRunning)
      return 1;

    bud_client_debug(client,
                     opposite,
                     "client %p throttle (%d) on %s",
                     ringbuffer_size(buf));

    err = uv_read_stop((uv_stream_t*) &opposite->tcp);
    if (err != 0) {
      bud_client_log(client,
                     opposite,
                     "client %p read_stop failed with (%d) \"%s\" on %s",
                     err,
                     uv_strerror(err));
      bud_client_close(client, opposite);
      return -1;
    }
    opposite->reading = kBudProgressNone;

    return 1;
  }

  return 0;
}


void bud_client_send(bud_client_t* client, bud_client_side_t* side) {
  char* out[RING_BUFFER_COUNT];
  uv_buf_t buf[RING_BUFFER_COUNT];
  size_t size[ARRAY_SIZE(out)];
  size_t count;
  size_t i;
  int r;

  /* Already writing */
  if (side->write != kBudProgressNone)
    return;

  /* If client is closed - stop sending */
  if (client->close == kBudProgressDone)
    return;

  count = ARRAY_SIZE(out);
  side->write_size = ringbuffer_read_nextv(&side->output, out, size, &count);
  if (side->write_size == 0)
    return;

  bud_client_debug(client,
                   side,
                   "client %p write(%d) on %s",
                   side->write_size);

  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);
  side->write_req.data = client;

  r = uv_write(&side->write_req,
               (uv_stream_t*) &side->tcp,
               buf,
               count,
               bud_client_send_cb);
  if (r == 0) {
    side->write = kBudProgressRunning;
    return;
  }

  side->write = kBudProgressDone;
  bud_client_log(client,
                 side,
                 "client %p uv_write() failed with (%d) \"%s\" on %s",
                 r,
                 uv_strerror(r));
  bud_client_close(client, side);
}


void bud_client_send_cb(uv_write_t* req, int status) {
  int r;
  bud_client_t* client;
  bud_client_side_t* side;
  bud_client_side_t* opposite;

  client = req->data;

  if (req == &client->frontend.write_req) {
    side = &client->frontend;
    opposite = &client->backend;
  } else {
    side = &client->backend;
    opposite = &client->frontend;
  }

  if (status != 0) {
    bud_client_log(client,
                   side,
                   "client %p uv_write() cb failed with (%d) \"%s\" on %s",
                   status,
                   uv_strerror(status));
    side->write = kBudProgressDone;
    return bud_client_close(client, side);
  }

  /* Consume written data */
  bud_client_debug(client,
                   side,
                   "client %p write_cb (%d) on: %s",
                   side->write_size);
  ringbuffer_read_skip(&side->output, side->write_size);

  side->write = kBudProgressNone;
  side->write_size = 0;

  /* Start reading, if stopped */
  if (opposite->reading == kBudProgressNone &&
      side->close != kBudProgressDone &&
      side->shutdown != kBudProgressDone &&
      !ringbuffer_is_full(&side->output)) {
    bud_client_debug(client,
                     opposite,
                     "client %p read_start (%d) on: %s",
                     0);
    r = uv_read_start((uv_stream_t*) &opposite->tcp,
                      bud_client_alloc_cb,
                      bud_client_read_cb);
    if (r != 0) {
      bud_client_log(client,
                     opposite,
                     "client %p uv_read_start() failed with (%d) \"%s\" on %s",
                     r,
                     uv_strerror(r));
      return bud_client_close(client, opposite);
    }
    opposite->reading = kBudProgressRunning;
  }

  /* Cycle again */
  bud_client_cycle(client);

  if (side->close == kBudProgressRunning ||
      side->shutdown == kBudProgressRunning) {
    if (!ringbuffer_is_empty(&side->output))
      return;

    /* No new data, destroy or shutdown */
    if (side->shutdown == kBudProgressRunning)
      bud_client_shutdown(client, side);
    else
      bud_client_close(client, side);
  }
}


void bud_client_connect_cb(uv_connect_t* req, int status) {
  bud_client_t* client;

  client = container_of(req, bud_client_t, connect_req);
  bud_client_debug(client,
                   &client->backend,
                   "client %p connect %d on %s",
                   status);

  if (status != 0 && status != UV_ECANCELED) {
    bud_client_log(client,
                   &client->backend,
                   "client %p uv_connect() failed with (%d) \"%s\" on %s",
                   status,
                   uv_strerror(status));
    return bud_client_close(client, &client->backend);
  }

  /* Do nothing, we will start reading once handshake will be performed */
}


void bud_client_shutdown(bud_client_t* client, bud_client_side_t* side) {
  int r;

  /* Ignore if already shutdown or destroyed */
  if (side->shutdown || client->close == kBudProgressDone)
    return;

  side->shutdown = kBudProgressNone;

  /* Try cycling data to figure out if there is still something to send */
  bud_client_cycle(client);

  /* Not empty, send everything first */
  if (!ringbuffer_is_empty(&side->output)) {
    side->shutdown = kBudProgressRunning;
    return;
  }

  bud_client_debug(client,
                   side,
                   "client %p shutdown (%d) on: %s",
                   0);

  if (side == &client->frontend && SSL_shutdown(client->ssl) == 0)
    SSL_shutdown(client->ssl);

  side->shutdown_req.data = client;
  r = uv_shutdown(&side->shutdown_req,
                  (uv_stream_t*) &side->tcp,
                  bud_client_shutdown_cb);
  if (r != 0) {
    bud_client_log(client,
                   side,
                   "client %p uv_shutdown() failed with (%d) \"%s\" on %s",
                   r,
                   uv_strerror(r));
    bud_client_close(client, side);
  }
  side->shutdown = 1;
}


void bud_client_shutdown_cb(uv_shutdown_t* req, int status) {
  bud_client_t* client;
  bud_client_side_t* side;

  client = req->data;
  if (req == &client->frontend.shutdown_req)
    side = &client->frontend;
  else
    side = &client->backend;

  side->shutdown = kBudProgressDone;

  if (status == UV_ECANCELED)
    return;

  if (status != 0) {
    bud_client_log(client,
                   side,
                   "client %p shutdown_cb() failed with (%d) \"%s\" on %s",
                   status,
                   uv_strerror(status));
  } else {
    bud_client_debug(client,
                     side,
                     "client %p shutdown cb (%d) on: %s",
                     0);
  }

  if (side->close == kBudProgressRunning)
    bud_client_close(client, side);
}


int bud_client_prepend_proxyline(bud_client_t* client) {
  int r;
  struct sockaddr_storage storage;
  int storage_size;
  struct sockaddr_in* addr;
  struct sockaddr_in6* addr6;
  const char* family;
  char host[INET6_ADDRSTRLEN];
  int16_t port;
  char proxyline[256];

  storage_size = sizeof(storage);
  r = uv_tcp_getpeername(&client->frontend.tcp,
                         (struct sockaddr*) &storage,
                         &storage_size);
  if (r != 0)
    return r;

  addr = (struct sockaddr_in*) &storage;
  addr6 = (struct sockaddr_in6*) &storage;
  if (storage.ss_family == AF_INET) {
    family = "TCP4";
    port = addr->sin_port;
    r = uv_inet_ntop(AF_INET, &addr->sin_addr, host, sizeof(host));
  } else if (storage.ss_family == AF_INET6) {
    family = "TCP6";
    port = addr6->sin6_port;
    r = uv_inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
  } else {
    return -1;
  }

  if (r != 0)
    return r;

  r = snprintf(proxyline,
               sizeof(proxyline),
               client->config->proxyline_fmt,
               family,
               host,
               ntohs(port));
  ASSERT(r < (int) sizeof(proxyline), "Client proxyline overflow");

  return (int) ringbuffer_write_into(&client->backend.input, proxyline, r);
}


const char* bud_side_str(bud_client_side_type_t side) {
  if (side == kBudFrontend)
    return "frontend";
  else
    return "backend";
}


const char* bud_sslerror_str(int err) {
  switch (err) {
    case SSL_ERROR_SSL:
      return "SSL";
    case SSL_ERROR_WANT_READ:
      return "WANT_READ";
    case SSL_ERROR_WANT_WRITE:
      return "WANT_WRITE";
    case SSL_ERROR_WANT_X509_LOOKUP:
      return "WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
      return "SYSCALL";
    case SSL_ERROR_ZERO_RETURN:
      return "ZERO_RETURN";
    case SSL_ERROR_WANT_CONNECT:
      return "WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
      return "WANT_ACCEPT";
    default:
      return "UKNOWN";
  }
}


void bud_client_log(bud_client_t* client,
                    bud_client_side_t* side,
                    const char* fmt,
                    int code,
                    const char* reason) {
  if (client->close == kBudProgressDone)
    return;
  bud_log(client->config,
          side->type == kBudBackend ? kBudLogWarning : kBudLogNotice,
          (char*) fmt,
          client,
          code,
          reason,
          bud_side_str(side->type));
}


void bud_client_debug(bud_client_t* client,
                      bud_client_side_t* side,
                      const char* fmt,
                      int code) {
  bud_log(client->config,
          kBudLogDebug,
          (char*) fmt,
          client,
          code,
          bud_side_str(side->type));
}
