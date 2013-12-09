#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>

#include "uv.h"
#include "bio.h"
#include "ringbuffer.h"
#include "openssl/bio.h"
#include "parson.h"

#include "common.h"
#include "client.h"
#include "client-private.h"
#include "hello-parser.h"
#include "http-pool.h"
#include "logger.h"
#include "sni.h"
#include "ocsp.h"

static void bud_client_side_init(bud_client_side_t* side,
                                 bud_client_side_type_t type,
                                 bud_client_t* client);
static void bud_client_side_destroy(bud_client_side_t* side);
static bud_client_side_t* bud_client_side_by_tcp(bud_client_t* client,
                                                 uv_tcp_t* tcp);
static void bud_client_close_cb(uv_handle_t* handle);
static void bud_client_alloc_cb(uv_handle_t* handle,
                                size_t suggested_size,
                                uv_buf_t* buf);
static void bud_client_read_cb(uv_stream_t* stream,
                               ssize_t nread,
                               const uv_buf_t* buf);
static void bud_client_parse_hello(bud_client_t* client);
static void bud_client_sni_cb(bud_http_request_t* req, bud_error_t err);
static int bud_client_backend_in(bud_client_t* client);
static int bud_client_backend_out(bud_client_t* client);
static int bud_client_throttle(bud_client_t* client,
                               bud_client_side_t* side,
                               ringbuffer* buf);
static int bud_client_send(bud_client_t* client, bud_client_side_t* side);
static void bud_client_send_cb(uv_write_t* req, int status);
static int bud_client_connect(bud_client_t* client);
static void bud_client_connect_cb(uv_connect_t* req, int status);
static void bud_client_connect_close_cb(uv_handle_t* handle);
static bud_error_t bud_client_retry(bud_client_t* client);
static void bud_client_retry_cb(uv_timer_t* timer, int status);
static int bud_client_shutdown(bud_client_t* client, bud_client_side_t* side);
static void bud_client_shutdown_cb(uv_shutdown_t* req, int status);
static int bud_client_prepend_proxyline(bud_client_t* client);
static const char* bud_sslerror_str(int err);
static void bud_client_ssl_info_cb(const SSL* ssl, int where, int ret);

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
  client->last_handshake = 0;
  client->handshakes = 0;
  client->connect = kBudProgressNone;
  client->close = kBudProgressNone;
  client->cycle = kBudProgressNone;
  client->recycle = 0;
  client->destroy_waiting = 0;

  client->hello_parse = kBudProgressDone;
  if (config->sni.enabled || config->stapling.enabled)
    client->hello_parse = kBudProgressNone;

  /* SNI */
  client->sni_req = NULL;
  client->sni_ctx.ctx = NULL;

  /* Stapling */
  client->stapling_cache_req = NULL;
  client->stapling_req = NULL;
  client->stapling_ocsp_resp = NULL;

  /* Availability */
  client->retry = kBudProgressNone;
  client->retry_count = 0;
  client->retry_timer.data = client;
  client->selected_backend = NULL;

  r = uv_timer_init(config->loop, &client->retry_timer);
  if (r != 0)
    goto failed_timer_init;
  client->destroy_waiting++;

  /* Initialize buffers */
  bud_client_side_init(&client->frontend, kBudFrontend, client);
  bud_client_side_init(&client->backend, kBudBackend, client);

  /**
   * Accept client on frontend
   */
  r = uv_tcp_init(config->loop, &client->frontend.tcp);
  if (r != 0)
    goto failed_tcp_in_init;

  client->destroy_waiting++;
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
   * Select a backend and connect to it, or wait for a backend to become
   * alive again.
   */
  client->selected_backend = bud_config_select_backend(config);

  /* No backend alive, try reconnecting */
  if (client->selected_backend->dead) {
    DBG_LN(&client->backend, "all backends dead, scheduling reconnection");
    if (!bud_is_ok(bud_client_retry(client)))
      r = -1;
  } else {
    r = bud_client_connect(client);
  }
  if (r != 0)
    goto failed_accept;

  /* Adjust sockets */
  r = uv_tcp_nodelay(&client->frontend.tcp, 1);
  if (r == 0 && config->frontend.keepalive > 0)
    r = uv_tcp_keepalive(&client->frontend.tcp, 1, config->frontend.keepalive);
  if (r != 0)
    goto failed_connect;

  /* Initialize SSL */

  /* First context is always default */
  client->ssl = SSL_new(config->contexts[0].ctx);
  if (client->ssl == NULL)
    goto failed_connect;

  if (!SSL_set_ex_data(client->ssl, kBudSSLClientIndex, client))
    goto failed_connect;

  SSL_set_info_callback(client->ssl, bud_client_ssl_info_cb);

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

  client->destroy_waiting = 3;
  DBG_LN(&client->frontend, "new");
  return;

failed_connect:
  client->connect = kBudProgressDone;
  client->close = kBudProgressDone;
  uv_close((uv_handle_t*) &client->backend.tcp, bud_client_close_cb);

failed_accept:
  uv_close((uv_handle_t*) &client->frontend.tcp, bud_client_close_cb);

failed_tcp_in_init:
  uv_close((uv_handle_t*) &client->retry_timer, bud_client_close_cb);
  return;

failed_timer_init:
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
  side->write_req = NULL;
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
      DBG_LN(side, "force closing");
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
  } else if (client->frontend.close != kBudProgressDone) {
    DBG_LN(&client->frontend, "force closing (and waiting for other)");
    uv_close((uv_handle_t*) &client->frontend.tcp, bud_client_close_cb);
    client->frontend.close = kBudProgressDone;
  }

  if (side->type == kBudFrontend &&
      !ringbuffer_is_empty(&client->backend.output)) {
    client->backend.close = kBudProgressRunning;
  } else if (client->backend.close != kBudProgressDone) {
    DBG_LN(&client->backend, "force closing (and waiting for other)");
    uv_close((uv_handle_t*) &client->backend.tcp, bud_client_close_cb);
    client->backend.close = kBudProgressDone;
  }

  /* Close side-independent handles */
  uv_close((uv_handle_t*) &client->retry_timer, bud_client_close_cb);

  /* Cycle data if one of backends is not closed */
  if (client->backend.close != kBudProgressDone ||
      client->frontend.close != kBudProgressDone) {
    bud_client_cycle(client);
  }
}


void bud_client_close_cb(uv_handle_t* handle) {
  bud_client_t* client;

  client = (bud_client_t*) handle->data;

  if (--client->destroy_waiting != 0)
    return;

  DBG_LN(&client->frontend, "close_cb");

  bud_client_side_destroy(&client->frontend);
  bud_client_side_destroy(&client->backend);

  if (client->ssl != NULL)
    SSL_free(client->ssl);
  if (client->sni_ctx.ctx != NULL)
    bud_context_free(&client->sni_ctx);
  if (client->sni_req != NULL)
    bud_http_request_cancel(client->sni_req);
  if (client->stapling_cache_req != NULL)
    bud_http_request_cancel(client->stapling_cache_req);
  if (client->stapling_req != NULL)
    bud_http_request_cancel(client->stapling_req);
  if (client->stapling_ocsp_resp != NULL)
    free(client->stapling_ocsp_resp);

  client->ssl = NULL;
  client->sni_req = NULL;
  client->stapling_cache_req = NULL;
  client->stapling_req = NULL;
  client->stapling_ocsp_resp = NULL;
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

  DBG(side, "after read_cb() => %d", nread);

  /* Handle EOF */
  if (nread == UV_EOF) {
    side->reading = kBudProgressDone;

    /* Shutdown opposite side */
    opposite = side == &client->frontend ? &client->backend : &client->frontend;
    if (bud_client_shutdown(client, opposite) != 0)
      return;
  }

  /* Try writing out data anyway */
  bud_client_cycle(client);

  if ((r != 0 || nread < 0) && nread != UV_EOF) {
    if (nread < 0)
      NOTICE(side, "read_cb failed: %d - \"%s\"", nread, uv_strerror(nread));
    else
      NOTICE(side, "write_append failed: %d", r);

    /* Unrecoverable socket error, close */
    return bud_client_close(client, side);
  }

  /* If buffer is full - stop reading */
  bud_client_throttle(client, side, &side->input);
}


void bud_client_cycle(bud_client_t* client) {
  /* Parsing, must wait */
  if (client->hello_parse != kBudProgressDone) {
    bud_client_parse_hello(client);
  } else if (client->cycle == kBudProgressRunning) {
    /* Recursive call detected, ask cycle loop to run one more time */
    client->recycle++;
  } else {
    client->cycle = kBudProgressRunning;
    do {
      client->recycle = 0;
      if (bud_client_backend_in(client) != 0)
        break;
      if (bud_client_backend_out(client) != 0)
        break;
      if (bud_client_send(client, &client->frontend) != 0)
        break;
      if (bud_client_send(client, &client->backend) != 0)
        break;

      if (client->recycle)
        DBG_LN(&client->frontend, "recycle");
    } while (client->recycle);
    client->cycle = kBudProgressNone;
  }
}


void bud_client_parse_hello(bud_client_t* client) {
  bud_config_t* config;
  bud_error_t err;
  char* data;
  size_t size;

  /* Already running, ignore */
  if (client->hello_parse != kBudProgressNone)
    return;

  if (ringbuffer_is_empty(&client->frontend.input))
    return;

  config = client->config;
  data = ringbuffer_read_next(&client->frontend.input, &size);
  err = bud_parse_client_hello(data, (size_t) size, &client->hello);

  /* Parser need more data, wait for it */
  if (err.code == kBudErrParserNeedMore)
    return;

  if (!bud_is_ok(err)) {
    NOTICE(&client->frontend,
           "failed to parse hello: %d - \"%s\"",
           err.code,
           err.str);
    goto fatal;
  }

  /* Parse success, perform SNI lookup */
  if (config->sni.enabled && client->hello.servername_len != 0) {
    client->sni_req = bud_http_get(config->sni.pool,
                                   config->sni.url,
                                   client->hello.servername,
                                   client->hello.servername_len,
                                   bud_client_sni_cb,
                                   &err);
    client->sni_req->data = client;
    if (!bud_is_ok(err)) {
      NOTICE(&client->frontend,
             "failed to request SNI: %d - \"%s\"",
             err.code,
             err.str);
      goto fatal;
    }

    client->hello_parse = kBudProgressRunning;
  /* Perform OCSP stapling request */
  } else if (config->stapling.enabled && client->hello.ocsp_request != 0) {
    err = bud_client_ocsp_stapling(client);
    if (!bud_is_ok(err))
      goto fatal;
  }

  if (client->hello_parse != kBudProgressNone)
    return;

  client->hello_parse = kBudProgressDone;
  bud_client_cycle(client);
  return;

fatal:
  client->hello_parse = kBudProgressDone;
  bud_client_close(client, &client->frontend);
}


void bud_client_sni_cb(bud_http_request_t* req, bud_error_t err) {
  bud_client_t* client;
  bud_config_t* config;
  bud_error_t sni_err;
  bud_error_t stapling_err;

  client = req->data;
  config = client->config;

  client->sni_req = NULL;
  client->hello_parse = kBudProgressDone;
  if (!bud_is_ok(err)) {
    WARNING(&client->frontend, "SNI cb failed: %d - \"%s\"", err.code, err.str);
    goto fatal;
  }

  if (req->code == 404) {
    /* Not found */
    DBG(&client->frontend,
        "SNI name not found: \"%.*s\"",
        client->hello.servername_len,
        client->hello.servername);
    goto done;
  }

  /* Parse incoming JSON */
  sni_err = bud_sni_from_json(config, req->response, &client->sni_ctx);
  if (!bud_is_ok(sni_err)) {
    WARNING(&client->frontend,
           "SNI from json failed: %d - \"%s\"",
           err.code,
           err.str);
    goto fatal;
  }

  /* Success */
  DBG(&client->frontend,
      "SNI name found: \"%.*s\"",
      client->hello.servername_len,
      client->hello.servername);
  if (!SSL_set_ex_data(client->ssl, kBudSSLSNIIndex, &client->sni_ctx)) {
    WARNING(&client->frontend,
           "Failed to set app data for SNI: \"%.*s\"",
           client->hello.servername_len,
           client->hello.servername);
    goto fatal;
  }

done:
  /* Request stapling info if needed */
  if (config->stapling.enabled && client->hello.ocsp_request != 0) {
    stapling_err = bud_client_ocsp_stapling(client);
    if (!bud_is_ok(stapling_err))
      goto fatal;
  }
  json_value_free(req->response);

  if (client->hello_parse == kBudProgressDone)
    bud_client_cycle(client);
  return;

fatal:
  bud_client_close(client, &client->frontend);
}


int bud_client_backend_in(bud_client_t* client) {
  char* data;
  size_t size;
  int written;
  int err;

  written = 0;
  while (!ringbuffer_is_empty(&client->backend.input)) {
    data = ringbuffer_read_next(&client->backend.input, &size);
    written = SSL_write(client->ssl, data, size);
    DBG(&client->frontend, "SSL_write() => %d", written);
    DBG(&client->frontend,
        "frontend.output => %d",
        ringbuffer_size(&client->frontend.output));
    if (written < 0)
      break;

    ASSERT(written == (int) size, "SSL_write() did unexpected partial write");
    ringbuffer_read_skip(&client->backend.input, written);

    /* info_cb() has closed front-end */
    if (client->frontend.close != kBudProgressNone)
      return -1;
  }

  if (bud_client_throttle(client,
                          &client->frontend,
                          &client->frontend.output) == -1) {
    /* Throttle error */
    return -1;
  }

  if (written >= 0)
    return 0;

  err = SSL_get_error(client->ssl, written);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return 0;

  NOTICE(&client->frontend,
         "SSL_write failed: %d - \"%s\"",
         err,
         bud_sslerror_str(err));
  bud_client_close(client, &client->frontend);
  return -1;
}


int bud_client_backend_out(bud_client_t* client) {
  int read;
  int err;
  size_t avail;
  char* out;

  /* If buffer is full - stop reading */
  err = bud_client_throttle(client,
                            &client->backend,
                            &client->backend.output);
  if (err < 0) {
    return err;
  } else if (err == 1) {
    return 0;
  }

  do {
    avail = 0;
    out = ringbuffer_write_ptr(&client->backend.output, &avail);
    read = SSL_read(client->ssl, out, avail);
    DBG(&client->frontend, "SSL_read() => %d", read);
    if (read > 0) {
      ringbuffer_write_append(&client->backend.output, read);
      if (bud_client_send(client, &client->backend) != 0)
        return -1;
    }

    /* info_cb() has closed front-end */
    if (client->frontend.close != kBudProgressNone)
      return -1;
  } while (read > 0);

  if (read > 0)
    return 0;

  err = SSL_get_error(client->ssl, read);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return 0;

  if (err != SSL_ERROR_ZERO_RETURN) {
    NOTICE(&client->frontend,
           "SSL_read failed : %d - \"%s\"",
           err,
           bud_sslerror_str(err));
  }
  bud_client_close(client, &client->frontend);
  return -1;
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

    DBG(opposite, "throttle, buffer full: %ld", ringbuffer_size(buf));

    err = uv_read_stop((uv_stream_t*) &opposite->tcp);
    if (err != 0) {
      NOTICE(opposite,
             "uv_read_stop failed: %d - \"%s\"",
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


int bud_client_send(bud_client_t* client, bud_client_side_t* side) {
  char* out[RING_BUFFER_COUNT];
  uv_buf_t buf[RING_BUFFER_COUNT];
  size_t size[ARRAY_SIZE(out)];
  size_t count;
  size_t i;
  int r;

  /* Already writing */
  if (side->write != kBudProgressNone)
    return 0;

  /* If client is closed - stop sending */
  if (client->close == kBudProgressDone)
    return 0;

  /* Backend still connecting */
  if (side == &client->backend && client->connect != kBudProgressDone)
    return 0;

  count = ARRAY_SIZE(out);
  side->write_size = ringbuffer_read_nextv(&side->output, out, size, &count);
  if (side->write_size == 0)
    return 0;

  DBG(side, "uv_write(%ld) iovcnt: %ld", side->write_size, count);

  side->write_req = malloc(sizeof(*side->write_req));
  if (side->write_req == NULL) {
    NOTICE_LN(side, "failed to allocate write_req");
    goto fatal;
  }

  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);
  side->write_req->data = client;

  r = uv_write(side->write_req,
               (uv_stream_t*) &side->tcp,
               buf,
               count,
               bud_client_send_cb);
  if (r != 0) {
    NOTICE(side,
           "uv_write() failed: %d - \"%s\"",
           r,
           uv_strerror(r));
    goto fatal;
  }

  /* Immediate write */
  if (side->tcp.write_queue_size == 0) {
    DBG_LN(side, "immediate write");
    side->write = kBudProgressNone;

    /* NOTE: not causing recursion */
    bud_client_send_cb(side->write_req, 0);
  } else {
    DBG_LN(side, "queued write");
    side->write = kBudProgressRunning;
  }
  return 0;

fatal:
  free(side->write_req);
  side->write = kBudProgressDone;
  side->write_req = NULL;
  bud_client_close(client, side);
  return -1;
}


void bud_client_send_cb(uv_write_t* req, int status) {
  int r;
  bud_client_t* client;
  bud_client_side_t* side;
  bud_client_side_t* opposite;
  int immediate;

  client = req->data;
  req->data = NULL;
  immediate = 0;

  /* Already processed, skip */
  if (client == NULL)
    goto done;

  if (req == client->frontend.write_req) {
    side = &client->frontend;
    opposite = &client->backend;
  } else {
    side = &client->backend;
    opposite = &client->frontend;
  }

  /* Closing, ignore */
  if (status == UV_ECANCELED)
    goto done;

  if (status != 0) {
    NOTICE(side,
           "uv_write() cb failed: %d - \"%s\"",
           status,
           uv_strerror(status));
    side->write = kBudProgressDone;
    return bud_client_close(client, side);
  }

  /* Consume written data */
  DBG(side, "write_cb => %d", side->write_size);
  ringbuffer_read_skip(&side->output, side->write_size);

  immediate = side->write == kBudProgressNone;
  side->write = kBudProgressNone;
  side->write_size = 0;
  side->write_req = NULL;

  /* Start reading, if stopped and not closing */
  if (opposite->reading == kBudProgressNone) {
    if ((client->retry == kBudProgressRunning ||
         client->connect == kBudProgressRunning) &&
        opposite == &client->backend) {
      /* Set reading mark on backend to resume it after reconnecting */
      opposite->reading = kBudProgressRunning;
    } else if (opposite->close != kBudProgressDone &&
               side->close != kBudProgressDone &&
               side->shutdown != kBudProgressDone &&
               !ringbuffer_is_full(&side->output)) {
      DBG_LN(opposite, "read_start");
      r = uv_read_start((uv_stream_t*) &opposite->tcp,
                        bud_client_alloc_cb,
                        bud_client_read_cb);
      if (r != 0) {
        NOTICE(opposite,
               "uv_read_start() failed: %d - \"%s\"",
               r,
               uv_strerror(r));
        return bud_client_close(client, opposite);
      }
      opposite->reading = kBudProgressRunning;
    }
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
done:
  if (!immediate)
    free(req);
}


int bud_client_connect(bud_client_t* client) {
  int r;
  bud_config_t* config;
  bud_config_backend_t* backend;

  config = client->config;
  backend = client->selected_backend;

  /*
   * Connect to backend
   * NOTE: We won't start reading until some SSL data will be sent.
   */
  r = uv_tcp_init(config->loop, &client->backend.tcp);
  if (r != 0)
    return r;
  client->backend.close = client->close;
  client->destroy_waiting++;

  if (r == 0)
    r = uv_tcp_nodelay(&client->backend.tcp, 1);
  if (r == 0 && backend->keepalive > 0)
    r = uv_tcp_keepalive(&client->backend.tcp, 1, backend->keepalive);
  if (r != 0)
    goto failed_connect;

  r = uv_tcp_connect(&client->connect_req,
                     &client->backend.tcp,
                     (struct sockaddr*) &backend->addr,
                     bud_client_connect_cb);
  if (r != 0)
    goto failed_connect;

  client->connect = kBudProgressRunning;

  return r;

failed_connect:
  uv_close((uv_handle_t*) &client->backend.tcp, bud_client_close_cb);

  /* TODO(indutny): report errors */
  return r;
}


void bud_client_connect_cb(uv_connect_t* req, int status) {
  int r;
  bud_client_t* client;

  if (status == UV_ECANCELED)
    return;

  client = container_of(req, bud_client_t, connect_req);
  DBG(&client->backend, "connect %d", status);

  client->selected_backend->last_checked = uv_now(client->config->loop);

  if (status != 0) {
    /* Error, try reconnecting */
    client->connect = kBudProgressNone;
    WARNING(&client->backend,
            "uv_connect() failed: %d - \"%s\"",
            status,
            uv_strerror(status));
    if (client->selected_backend->dead_since == 0)
      client->selected_backend->dead_since = uv_now(client->config->loop);

    /* But reopen the socket first */
    client->destroy_waiting--;
    uv_close((uv_handle_t*) &client->backend.tcp, bud_client_connect_close_cb);
    client->backend.close = kBudProgressDone;
    return;
  }

  /* Success */
  client->connect = kBudProgressDone;

  /* Start reading if queued */
  if (client->backend.reading == kBudProgressRunning) {
    r = uv_read_start((uv_stream_t*) &client->backend.tcp,
                      bud_client_alloc_cb,
                      bud_client_read_cb);
    if (r != 0) {
      WARNING(&client->backend,
              "uv_read_start() failed: %d - \"%s\"",
              r,
              uv_strerror(r));
      return;
    }
  }

  /* Cycle data anyway */
  bud_client_cycle(client);
}


void bud_client_connect_close_cb(uv_handle_t* handle) {
  bud_error_t err;
  bud_client_t* client;

  client = handle->data;

  err = bud_client_retry(client);
  if (bud_is_ok(err))
    return;

  WARNING(&client->backend,
          "bud_client_retry() failed: %d - \"%s\"",
          err.code,
          err.str);
  bud_client_close(client, &client->backend);
}


bud_error_t bud_client_retry(bud_client_t* client) {
  int r;

  if (++client->retry_count > client->config->availability.max_retries) {
    WARNING_LN(&client->backend, "Retried too many times");
    return bud_error(kBudErrMaxRetries);
  }

  /* Select backend again */
  client->selected_backend = bud_config_select_backend(client->config);

  client->retry = kBudProgressNone;
  r = uv_timer_start(&client->retry_timer,
                     bud_client_retry_cb,
                     client->config->availability.retry_interval,
                     0);
  if (r != 0)
    return bud_error_num(kBudErrRetryTimerStart, r);
  client->retry = kBudProgressRunning;

  return bud_ok();
}


void bud_client_retry_cb(uv_timer_t* timer, int status) {
  int r;
  bud_client_t* client;

  if (status == UV_ECANCELED)
    return;

  client = timer->data;
  client->retry = kBudProgressDone;

  r = status;
  if (r == 0)
    r = bud_client_connect(client);
  if (r < 0) {
    WARNING(&client->backend,
            "bud_client_retry_cb() failure: %d - \"%s\"",
            r,
            uv_strerror(r));
    bud_client_close(client, &client->backend);
    return;
  }
}


int bud_client_shutdown(bud_client_t* client, bud_client_side_t* side) {
  int r;

  /* Ignore if already shutdown or destroyed */
  if (side->shutdown || client->close == kBudProgressDone)
    return 0;

  side->shutdown = kBudProgressNone;

  /* Try cycling data to figure out if there is still something to send */
  bud_client_cycle(client);

  /* Not empty, send everything first */
  if (!ringbuffer_is_empty(&side->output)) {
    side->shutdown = kBudProgressRunning;
    return 0;
  }

  DBG_LN(side, "shutdown");

  if (side == &client->frontend) {
    if (SSL_shutdown(client->ssl) == 0)
      SSL_shutdown(client->ssl);

    /* Try writing close_notify */
    if (bud_client_send(client, &client->frontend) != 0)
      goto fatal;
  }

  side->shutdown_req.data = client;
  r = uv_shutdown(&side->shutdown_req,
                  (uv_stream_t*) &side->tcp,
                  bud_client_shutdown_cb);
  if (r != 0) {
    NOTICE(side, "uv_shutdown() failed: %d - \"%s\"", r, uv_strerror(r));
    bud_client_close(client, side);
  }

fatal:
  side->shutdown = 1;

  /* Just to let know callers that we have closed the client */
  return -1;
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
    NOTICE(side,
           "shutdown_cb() failed: %d - \"%s\"",
           status,
           uv_strerror(status));
  } else {
    DBG_LN(side, "shutdown cb");
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


void bud_client_ssl_info_cb(const SSL* ssl, int where, int ret) {
  bud_client_t* client;
  uint64_t now;
  uint64_t limit;

  if ((where & SSL_CB_HANDSHAKE_START) == 0)
    return;

  client = SSL_get_ex_data(ssl, kBudSSLClientIndex);
  now = uv_now(client->config->loop);

  /* NOTE: config's limit is in ms */
  limit = (uint64_t) client->config->frontend.reneg_window;
  if (now - client->last_handshake > limit)
    client->handshakes = 0;

  /* First handshake */
  if (client->last_handshake == 0)
    goto end;
  DBG(&client->frontend, "renegotation %d", client->handshakes);

  /* Too many renegotiations in a small time window */
  if (++client->handshakes > client->config->frontend.reneg_limit) {
    WARNING_LN(&client->frontend, "TLS renegotiation attack mitigated");
    bud_client_close(client, &client->frontend);
  }

end:
  client->last_handshake = now;
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
                    bud_log_level_t level,
                    const char* fmt,
                    ...) {
  va_list pa;

  if (client->close == kBudProgressDone)
    return;

  va_start(pa, fmt);
  bud_logva(client->config, level, fmt, pa);
  va_end(pa);
}
