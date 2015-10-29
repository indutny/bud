#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>
#include <string.h>  /* strlen */

#include "uv.h"
#include "bio.h"
#include "ringbuffer.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include "parson.h"

#include "src/avail.h"
#include "src/common.h"
#include "src/client.h"
#include "src/client-common.h"
#include "src/http-pool.h"
#include "src/logger.h"
#include "src/sni.h"
#include "src/ocsp.h"
#include "src/tracing.h"
#include "src/xforward.h"

static void bud_client_side_init(bud_client_side_t* side,
                                 bud_client_side_type_t type,
                                 bud_client_t* client);
static void bud_client_side_destroy(bud_client_side_t* side);
static bud_client_side_t* bud_client_side_by_tcp(bud_client_t* client,
                                                 uv_tcp_t* tcp);
static bud_client_error_t bud_client_on_hello(bud_client_t* client);
static void bud_client_sni_cb(bud_http_request_t* req, bud_error_t err);
static bud_client_error_t bud_client_backend_in(bud_client_t* client);
static bud_client_error_t bud_client_backend_out(bud_client_t* client);
static bud_client_error_t bud_client_throttle(bud_client_t* client,
                                              bud_client_side_t* side,
                                              ringbuffer* buf);
static bud_client_error_t bud_client_send(bud_client_t* client,
                                          bud_client_side_t* side);
static void bud_client_send_cb(uv_write_t* req, int status);
static bud_client_error_t bud_client_shutdown(bud_client_t* client,
                                              bud_client_side_t* side);
static void bud_client_shutdown_cb(uv_shutdown_t* req, int status);
static bud_client_error_t bud_client_fill_host(bud_client_t* client,
                                               bud_client_host_t* host);
static void bud_client_handshake_start_cb(const SSL* ssl);
static void bud_client_handshake_done_cb(const SSL* ssl);
static void bud_client_ssl_info_cb(const SSL* ssl, int where, int ret);
static const char* bud_client_get_peer_name(bud_client_t* client);

void bud_client_create(bud_config_t* config, uv_stream_t* stream) {
  int r;
  bud_client_t* client;
  bud_client_error_t cerr;
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

  client->id = bud_config_get_client_id(config);

  client->async_hello = kBudProgressDone;
  if (config->sni.enabled || config->stapling.enabled)
    client->async_hello = kBudProgressNone;

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
  client->backend_list = NULL;
  client->selected_backend = NULL;

  /* Proxyline */
  client->proxyline_waiting = 2;

  /* X-Forward */
  client->xforward.skip = 0;
  client->xforward.crlf = 0;

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

  cerr = bud_client_read_start(client, &client->frontend);
  if (!bud_is_ok(cerr.err))
    goto failed_accept;
  client->frontend.reading = kBudProgressRunning;

  /* Fill hosts */
  cerr = bud_client_fill_host(client, &client->local);
  if (!bud_is_ok(cerr.err))
    goto failed_accept;

  cerr = bud_client_fill_host(client, &client->remote);
  if (!bud_is_ok(cerr.err))
    goto failed_accept;

  /*
   * Select a backend and connect to it, or wait for a backend to become
   * alive again.
   */
  /* SNI backend comes from `backend` or sni callback */
  client->backend_list = &config->contexts[0].backend;
  client->balance = config->balance_e;
  if (client->balance == kBudBalanceSNI) {
    client->selected_backend = NULL;
    client->connect = kBudProgressRunning;
  } else {
    client->selected_backend = bud_select_backend(client);
  }

  /* No backend can be selected yet, wait for SNI */
  if (client->selected_backend == NULL) {
    client->backend.close = kBudProgressDone;
    cerr = bud_client_ok(&client->backend);

  /* No backend alive, try reconnecting */
  } else if (client->selected_backend->dead) {
    DBG_LN(&client->backend, "all backends dead, scheduling reconnection");
    cerr = bud_client_retry(client);

  /* Backend alive - connect immediately */
  } else {
    cerr = bud_client_connect(client);
  }
  if (!bud_is_ok(cerr.err))
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

  SSL_set_cert_cb(client->ssl, bud_client_ssl_cert_cb, client);
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

  bud_trace_frontend_accept(client);
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


void bud_client_close(bud_client_t* client, bud_client_error_t err) {
  bud_client_side_t* side;

  bud_trace_close(client, err.err);

  side = err.side;
  if (bud_is_ok(err.err) ||
      (err.err.code == kBudErrClientSSLRead &&
           err.err.data.ret == SSL_ERROR_ZERO_RETURN)) {
    DBG_LN(side, "bud_client_close()");
  } else if (side == &client->backend) {
    WARNING(side, "closed because: %s", bud_error_to_str(err.err));
  } else {
    NOTICE(side, "closed because: %s", bud_error_to_str(err.err));
  }

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
    err = bud_client_cycle(client);
    if (!bud_is_ok(err.err))
      return bud_client_close(client, err);
  }
}


void bud_client_close_cb(uv_handle_t* handle) {
  bud_client_t* client;

  client = (bud_client_t*) handle->data;

  if (--client->destroy_waiting != 0)
    return;

  bud_trace_end(client);
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
  bud_client_error_t cerr;

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
    cerr = bud_client_shutdown(client, opposite);
    if (!bud_is_ok(cerr.err))
      goto done;
  }

  /* Try writing out data anyway */
  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    goto done;

  if ((r != 0 || nread < 0) && nread != UV_EOF) {
    if (nread < 0)
      cerr = bud_client_error(bud_error_num(kBudErrClientReadCb, nread), side);
    else
      cerr = bud_client_error(bud_error(kBudErrClientWriteAppend), side);

    /* Unrecoverable socket error, close */
    return bud_client_close(client, cerr);
  }

  /* If buffer is full - stop reading */
  cerr = bud_client_throttle(client, side, &side->input);

done:
  if (!bud_is_ok(cerr.err) && cerr.err.code != kBudErrClientThrottle)
    bud_client_close(client, cerr);
}


bud_client_error_t bud_client_cycle(bud_client_t* client) {
  bud_client_error_t cerr;

  /* Parsing, must wait */
  if (client->cycle == kBudProgressRunning) {
    /* Recursive call detected, ask cycle loop to run one more time */
    client->recycle++;

    return bud_client_ok(&client->frontend);
  } else {
    client->cycle = kBudProgressRunning;
    cerr = bud_client_ok(&client->frontend);
    do {
      client->recycle = 0;
      cerr = bud_client_backend_in(client);
      if (!bud_is_ok(cerr.err) || client->close != kBudProgressNone)
        break;
      cerr = bud_client_backend_out(client);
      if (!bud_is_ok(cerr.err) || client->close != kBudProgressNone)
        break;
      cerr = bud_client_send(client, &client->frontend);
      if (!bud_is_ok(cerr.err) || client->close != kBudProgressNone)
        break;
      cerr = bud_client_send(client, &client->backend);
      if (!bud_is_ok(cerr.err) || client->close != kBudProgressNone)
        break;

      if (client->recycle)
        DBG_LN(&client->frontend, "recycle");
    } while (client->recycle);
    client->cycle = kBudProgressNone;

    if (!bud_is_ok(cerr.err))
      bud_client_close(client, cerr);

    return cerr;
  }
}


void bud_client_sni_cb(bud_http_request_t* req, bud_error_t err) {
  bud_client_t* client;
  bud_config_t* config;
  bud_client_error_t cerr;
  int r;
  STACK_OF(X509)* chain;
  SSL_CTX* ctx;
  X509* x509;
  EVP_PKEY* pkey;

  client = req->data;
  config = client->config;

  client->sni_req = NULL;
  client->async_hello = kBudProgressDone;
  if (!bud_is_ok(err)) {
    WARNING(&client->frontend, "SNI cb failed: \"%s\"", bud_error_to_str(err));
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
  err = bud_sni_from_json(config, req->response, &client->sni_ctx);
  if (!bud_is_ok(err)) {
    WARNING(&client->frontend,
            "SNI from json failed: \"%s\"",
            bud_error_to_str(err));
    goto fatal;
  }

  /* Success */
  DBG(&client->frontend,
      "SNI name found: \"%.*s\"",
      client->hello.servername_len,
      client->hello.servername);
  if (!SSL_set_ex_data(client->ssl, kBudSSLSNIIndex, &client->sni_ctx)) {
    err = bud_error(kBudErrClientSetExData);
    goto fatal;
  }

  /* NOTE: reference count is not increased by this API methods */
  ctx = client->sni_ctx.ctx;
  x509 = SSL_CTX_get0_certificate(ctx);
  pkey = SSL_CTX_get0_privatekey(ctx);

  r = SSL_CTX_get0_chain_certs(ctx, &chain);
  if (r == 1)
    r = SSL_use_certificate(client->ssl, x509);
  if (r == 1)
    r = SSL_use_PrivateKey(client->ssl, pkey);
  if (r == 1 && chain != NULL)
    r = SSL_set1_chain(client->ssl, chain);
  if (r != 1) {
    err = bud_error(kBudErrClientSetSNICert);
    goto fatal;
  }

  /* Update context, may be needed for early ticket key generation */
  SSL_set_SSL_CTX(client->ssl, ctx);

  /* Do not loose the cert callback! */
  SSL_set_cert_cb(client->ssl, bud_client_ssl_cert_cb, client);
  client->ssl->options = client->sni_ctx.ctx->options;

done:
  /* Request stapling info if needed */
  if (config->stapling.enabled && client->hello.ocsp_request != 0) {
    err = bud_client_ocsp_stapling(client);
    if (!bud_is_ok(err))
      goto fatal;
  }
  json_value_free(req->response);

  if (client->async_hello == kBudProgressDone) {
    cerr = bud_client_cycle(client);
    if (!bud_is_ok(cerr.err))
      bud_client_close(client, cerr);
  }
  return;

fatal:
  bud_client_close(client, bud_client_error(err, &client->frontend));
}


bud_client_error_t bud_client_backend_in(bud_client_t* client) {
  size_t size;
  int written;
  int err;
  bud_client_error_t cerr;

  written = 0;
  while (!ringbuffer_is_empty(&client->backend.input)) {
    char* data;

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
      return bud_client_ok(&client->backend);
  }

  cerr = bud_client_throttle(client,
                             &client->frontend,
                             &client->frontend.output);
  if (!bud_is_ok(cerr.err) && cerr.err.code != kBudErrClientThrottle)
    return cerr;

  if (written >= 0)
    return bud_client_ok(&client->backend);

  err = SSL_get_error(client->ssl, written);
  if (err == SSL_ERROR_WANT_READ ||
      err == SSL_ERROR_WANT_WRITE ||
      err == SSL_ERROR_WANT_X509_LOOKUP) {
    return bud_client_ok(&client->backend);
  }

  return bud_client_error(bud_error_num(kBudErrClientSSLWrite, err),
                          &client->backend);
}


bud_client_error_t bud_client_backend_out(bud_client_t* client) {
  int read;
  int err;
  size_t avail;
  char* out;
  bud_client_error_t cerr;

  /* If buffer is full - stop reading */
  cerr = bud_client_throttle(client,
                             &client->backend,
                             &client->backend.output);
  if (cerr.err.code == kBudErrClientThrottle)
    return bud_client_ok(&client->frontend);
  else if (!bud_is_ok(cerr.err))
    return cerr;

  do {
    avail = 0;
    out = ringbuffer_write_ptr(&client->backend.output, &avail);
    read = SSL_read(client->ssl, out, avail);
    DBG(&client->frontend, "SSL_read() => %d", read);
    if (read > 0) {
      ringbuffer_write_append(&client->backend.output, read);
      if (client->selected_backend->xforward &&
          !bud_client_xforward_done(client)) {
        cerr = bud_client_prepend_xforward(client);
        if (!bud_is_ok(cerr.err))
          return cerr;
      }

      cerr = bud_client_send(client, &client->backend);
      if (!bud_is_ok(cerr.err))
        return cerr;
    }

    /* info_cb() has closed front-end */
    if (client->close != kBudProgressNone)
      return bud_client_ok(&client->frontend);
  } while (read > 0);

  if (read > 0)
    goto success;

  err = SSL_get_error(client->ssl, read);
  if (err == SSL_ERROR_WANT_READ ||
      err == SSL_ERROR_WANT_WRITE ||
      err == SSL_ERROR_WANT_X509_LOOKUP) {
    goto success;
  }

  /* Close-notify, most likely */
  if (err == SSL_ERROR_ZERO_RETURN)
    return bud_client_shutdown(client, &client->backend);

  return bud_client_error(bud_error_num(kBudErrClientSSLRead, err),
                          &client->frontend);

success:
  return bud_client_ok(&client->backend);
}


bud_client_error_t bud_client_throttle(bud_client_t* client,
                                       bud_client_side_t* side,
                                       ringbuffer* buf) {
  int err;
  bud_client_side_t* opposite;

  if (!ringbuffer_is_full(buf))
    return bud_client_ok(side);

  opposite = side == &client->frontend ? &client->backend : &client->frontend;
  if (opposite->reading != kBudProgressRunning)
    goto done;

  DBG(opposite, "throttle, buffer full: %ld", ringbuffer_size(buf));

  err = uv_read_stop((uv_stream_t*) &opposite->tcp);
  if (err != 0) {
    NOTICE(opposite,
           "uv_read_stop failed: %d - \"%s\"",
           err,
           uv_strerror(err));
    return bud_client_error(bud_error_num(kBudErrClientReadStop, err), side);
  }
  opposite->reading = kBudProgressNone;

done:
  return bud_client_error(bud_error(kBudErrClientThrottle), side);
}


bud_client_error_t bud_client_send(bud_client_t* client,
                                   bud_client_side_t* side) {
  char* out[RING_BUFFER_COUNT];
  uv_buf_t buf[RING_BUFFER_COUNT];
  uv_buf_t* pbuf;
  size_t size[ARRAY_SIZE(out)];
  size_t count;
  size_t i;
  int r;
  bud_client_error_t cerr;

  /* Already writing */
  if (side->write != kBudProgressNone)
    goto done;

  /* If client is closed - stop sending */
  if (client->close == kBudProgressDone)
    goto done;

  /* Backend still connecting */
  if (side == &client->backend && client->connect != kBudProgressDone)
    goto done;

  count = ARRAY_SIZE(out);
  side->write_size = ringbuffer_read_nextv(&side->output, out, size, &count);
  if (side->write_size == 0)
    goto done;

  DBG(side, "uv_write(%ld) iovcnt: %ld", side->write_size, count);

  side->write_req.data = client;
  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);

  /* Try writing without queueing first */
  r = uv_try_write((uv_stream_t*) &side->tcp, buf, count);
  ASSERT((r >= 0 && (size_t) r <= side->write_size) || r < 0,
         "Value returned by uv_try_write is OOB");

  /* Fully written */
  if (r == (int) side->write_size) {
    DBG_LN(side, "immediate write");

    /* NOTE: not causing recursion */
    bud_client_send_cb(&side->write_req, 0);
    goto done;
  } if (r == UV_ENOSYS || r == UV_EAGAIN) {
    /* Not supported try_write */
    r = 0;
  } else if (r < 0) {
    cerr = bud_client_error(bud_error_num(kBudErrClientTryWrite, r), side);
    goto fatal;
  }

  /* Skip partially written bytes */
  ringbuffer_read_skip(&side->output, r);

  /* Partially written */
  side->write_size -= r;
  pbuf = buf;
  for (; r > 0; pbuf++, count--) {
    if ((int) pbuf->len > r) {
      /* Split */
      pbuf->base += r;
      pbuf->len -= r;
      r = 0;
      break;
    } else {
      r -= pbuf->len;
    }
  }
  DBG(side, "async uv_write(%ld) follow up: %ld", side->write_size, count);

  r = uv_write(&side->write_req,
               (uv_stream_t*) &side->tcp,
               pbuf,
               count,
               bud_client_send_cb);
  if (r != 0) {
    cerr = bud_client_error(bud_error_num(kBudErrClientWrite, r), side);
    goto fatal;
  }

  DBG_LN(side, "queued write");
  side->write = kBudProgressRunning;

done:
  return bud_client_ok(side);

fatal:
  side->write = kBudProgressDone;
  return cerr;
}


void bud_client_send_cb(uv_write_t* req, int status) {
  bud_client_t* client;
  bud_client_error_t cerr;
  bud_client_side_t* side;
  bud_client_side_t* opposite;

  /* Closing, ignore */
  if (status == UV_ECANCELED)
    return;

  client = req->data;

  if (req == &client->frontend.write_req) {
    side = &client->frontend;
    opposite = &client->backend;
  } else {
    side = &client->backend;
    opposite = &client->frontend;
  }

  if (status != 0) {
    side->write = kBudProgressDone;
    bud_client_close(
        client,
        bud_client_error(bud_error_num(kBudErrClientWriteCb, status), side));
    return;
  }

  /* Consume written data */
  DBG(side, "write_cb => %d", side->write_size);
  ringbuffer_read_skip(&side->output, side->write_size);

  /* Skip data in xforward parser */
  if (side == &client->backend)
    bud_client_xforward_skip(client, side->write_size);

  side->write = kBudProgressNone;
  side->write_size = 0;

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
      cerr = bud_client_read_start(client, opposite);
      if (!bud_is_ok(cerr.err))
        return bud_client_close(client, cerr);
      opposite->reading = kBudProgressRunning;
    }
  }

  /* Cycle again */
  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    return bud_client_close(client, cerr);

  if (side->close == kBudProgressRunning ||
      side->shutdown == kBudProgressRunning) {
    if (!ringbuffer_is_empty(&side->output))
      return;

    /* No new data, destroy or shutdown */
    if (side->shutdown == kBudProgressRunning) {
      cerr = bud_client_shutdown(client, side);
      if (!bud_is_ok(cerr.err))
        bud_client_close(client, cerr);
      return;
    }
    bud_client_close(client, bud_client_ok(side));
  }
}


bud_client_error_t bud_client_shutdown(bud_client_t* client,
                                       bud_client_side_t* side) {
  int r;
  bud_client_error_t cerr;

  /* Ignore if already shutdown or destroyed */
  if (side->shutdown != kBudProgressNone || client->close == kBudProgressDone)
    return bud_client_ok(side);

  /* Do not shutdown not-connected socket */
  if (side == &client->backend && client->connect != kBudProgressDone)
    return bud_client_error(bud_error(kBudErrClientShutdownNoConn), side);

  /* Try cycling data to figure out if there is still something to send */
  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    return cerr;

  /* Not empty, send everything first */
  if (!ringbuffer_is_empty(&side->output)) {
    side->shutdown = kBudProgressRunning;
    return bud_client_ok(side);
  }

  DBG_LN(side, "shutdown");

  if (side == &client->frontend) {
    if (SSL_shutdown(client->ssl) != 1)
      SSL_shutdown(client->ssl);

    /* Try writing close_notify */
    cerr = bud_client_send(client, &client->frontend);
    if (!bud_is_ok(cerr.err))
      goto fatal;
  }

  side->shutdown_req.data = client;
  r = uv_shutdown(&side->shutdown_req,
                  (uv_stream_t*) &side->tcp,
                  bud_client_shutdown_cb);
  if (r != 0) {
    cerr = bud_client_error(bud_error_num(kBudErrClientShutdown, r), side);
  } else {
    cerr = bud_client_ok(side);
    side->shutdown = kBudProgressRunning;
  }

fatal:
  side->shutdown = kBudProgressDone;

  return cerr;
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

  if (status == 0)
    DBG_LN(side, "shutdown cb");

  if (status != 0) {
    bud_client_close(client,
                     bud_client_error(bud_error_num(kBudErrClientShutdownCb,
                                                    status),
                                      side));

  /* If either closing, or shutdown both sides - kill both sockets! */
  } else if (side->close == kBudProgressRunning ||
             client->frontend.shutdown == client->backend.shutdown ||
             (side == &client->frontend &&
                  !client->config->frontend.allow_half_open)) {
    bud_client_close(client, bud_client_ok(side));
  }
}


bud_client_error_t bud_client_fill_host(bud_client_t* client,
                                        bud_client_host_t* host) {
  int r;
  struct sockaddr_storage storage;
  int storage_size;
  struct sockaddr_in* addr;
  struct sockaddr_in6* addr6;

  storage_size = sizeof(storage);
  if (host == &client->remote) {
    r = uv_tcp_getpeername(&client->frontend.tcp,
                           (struct sockaddr*) &storage,
                           &storage_size);
  } else {
    r = uv_tcp_getsockname(&client->frontend.tcp,
                           (struct sockaddr*) &storage,
                           &storage_size);
  }
  if (r != 0)
    goto fatal;

  addr = (struct sockaddr_in*) &storage;
  addr6 = (struct sockaddr_in6*) &storage;
  host->family = storage.ss_family;
  if (storage.ss_family == AF_INET) {
    host->port = addr->sin_port;
    r = uv_inet_ntop(AF_INET,
                     &addr->sin_addr,
                     host->host,
                     sizeof(host->host));
  } else if (storage.ss_family == AF_INET6) {
    host->port = addr6->sin6_port;
    r = uv_inet_ntop(AF_INET6,
                     &addr6->sin6_addr,
                     host->host,
                     sizeof(host->host));
  } else {
    r = -1;
    goto fatal;
  }

  if (r != 0)
    goto fatal;

  host->host_len = strlen(host->host);

  return bud_client_ok(&client->backend);

fatal:
  return bud_client_error(bud_error_num(kBudErrClientProxyline, r),
                          &client->backend);
}


bud_client_error_t bud_client_prepend_proxyline(bud_client_t* client) {
  int r;
  const char* family;
  char proxyline[1024];
  bud_config_proxyline_t type;

  /*
   * Client should both handshake and connect to backend in order to
   * be able to send proper proxyline
   */
  if (--client->proxyline_waiting != 0)
    return bud_client_ok();

  type = client->selected_backend->proxyline;

  if (type == kBudProxylineNone)
    return bud_client_ok();

  if (client->remote.family == AF_INET) {
    family = "TCP4";
  } else if (client->remote.family == AF_INET6) {
    family = "TCP6";
  } else {
    r = -1;
    goto fatal;
  }

  if (type == kBudProxylineHAProxy) {
    r = snprintf(proxyline,
                 sizeof(proxyline),
                 client->config->proxyline_fmt.haproxy,
                 family,
                 client->remote.host,
                 ntohs(client->remote.port));
  } else {
    const char* cn;

    cn = bud_client_get_peer_name(client);
    r = snprintf(proxyline,
                 sizeof(proxyline),
                 client->config->proxyline_fmt.json,
                 family,
                 client->remote.host,
                 ntohs(client->remote.port),
                 cn != NULL ? '"' : 'f',
                 cn != NULL ? cn : "als",
                 cn != NULL ? '"' : 'e');
  }
  ASSERT(0 <= r && r < (int) sizeof(proxyline), "Client proxyline overflow");

  r = ringbuffer_insert(&client->backend.output,
                        0,
                        proxyline,
                        (size_t) r);
  if (r != 0)
    goto fatal;

  return bud_client_ok(&client->backend);

fatal:
  return bud_client_error(bud_error_num(kBudErrClientProxyline, r),
                          &client->backend);
}


void bud_client_handshake_start_cb(const SSL* ssl) {
  bud_client_t* client;
  uint64_t now;
  uint64_t limit;

  client = SSL_get_ex_data(ssl, kBudSSLClientIndex);

  now = uv_now(client->config->loop);

  /* NOTE: config's limit is in ms */
  limit = (uint64_t) client->config->frontend.reneg_window * 1000;
  if (now - client->last_handshake > limit)
    client->handshakes = 0;

  /* First handshake */
  if (client->last_handshake == 0)
    goto end;
  DBG(&client->frontend, "renegotation %d", client->handshakes);

  /* Too many renegotiations in a small time window */
  if (++client->handshakes > client->config->frontend.reneg_limit) {
    bud_client_close(
        client,
        bud_client_error(bud_error(kBudErrClientRenegotiationAttack),
                         &client->frontend));
  }

end:
  client->last_handshake = now;
}


void bud_client_handshake_done_cb(const SSL* ssl) {
  bud_client_t* client;
  bud_context_t* context;
  bud_client_error_t cerr;

  client = SSL_get_ex_data(ssl, kBudSSLClientIndex);
  context = SSL_get_ex_data(ssl, kBudSSLSNIIndex);

  bud_trace_handshake(client);

  cerr = bud_client_ok();
  if (client->selected_backend != NULL)
    goto fatal;

  if (client->config->balance_e != kBudBalanceSNI)
    goto fatal;

  if (context != NULL && context->backend.count != 0) {
    client->backend_list = &context->backend;
    client->balance = context->balance_e;
  }
  if (client->backend_list != NULL)
    client->selected_backend = bud_select_backend(client);
  if (client->selected_backend != NULL) {
    /* Backend provided - connect */
    cerr = bud_client_connect(client);
  } else {
    /* No backend in SNI response */
    cerr = bud_client_error(bud_error(kBudErrClientNoBackendInSNI),
                            &client->frontend);
  }

fatal:
  /* Prepend proxyline if configured any */
  if (bud_is_ok(cerr.err))
    cerr = bud_client_prepend_proxyline(client);
  if (!bud_is_ok(cerr.err))
    bud_client_close(client, cerr);
}


int bud_client_ssl_cert_cb(SSL* ssl, void* arg) {
  bud_client_t* client;
  bud_client_error_t err;
  SSL_SESSION* sess;

  client = (bud_client_t*) arg;

  DBG(&client->backend, "ssl_cert_cb {%d}", client->async_hello);

  /* Finished, or no need to perform anything async */
  if (client->async_hello == kBudProgressDone)
    return 1;

  /* Already running, please wait */
  if (client->async_hello == kBudProgressRunning)
    return -1;

  /* Set hello */
  sess = SSL_get_session(ssl);
  if (sess == NULL || sess->tlsext_hostname == NULL) {
    client->hello.servername = NULL;
    client->hello.servername_len = 0;
  } else {
    client->hello.servername = sess->tlsext_hostname;
    client->hello.servername_len = strlen(sess->tlsext_hostname);
  }
  client->hello.ocsp_request =
      ssl->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp ? 1 : 0;

  err = bud_client_on_hello(client);
  if (!bud_is_ok(err.err))
    return 0;

  return -1;
}


bud_client_error_t bud_client_on_hello(bud_client_t* client) {
  bud_config_t* config;
  bud_error_t err;

  config = client->config;

  /* Perform SNI lookup */
  if (config->sni.enabled && client->hello.servername_len != 0) {
    client->sni_req = bud_http_get(config->sni.pool,
                                   config->sni.url,
                                   client->hello.servername,
                                   client->hello.servername_len,
                                   bud_client_sni_cb,
                                   &err);
    if (!bud_is_ok(err)) {
      NOTICE(&client->frontend,
             "failed to request SNI: \"%s\"",
             bud_error_to_str(err));
      goto fatal;
    }

    client->sni_req->data = client;
    client->async_hello = kBudProgressRunning;
  /* Perform OCSP stapling request */
  } else if (config->stapling.enabled && client->hello.ocsp_request != 0) {
    err = bud_client_ocsp_stapling(client);
    if (!bud_is_ok(err))
      goto fatal;
  }

  if (client->async_hello != kBudProgressNone)
    return bud_client_ok(&client->frontend);

  client->async_hello = kBudProgressDone;
  return bud_client_cycle(client);

fatal:
  client->async_hello = kBudProgressDone;
  return bud_client_error(err, &client->frontend);
}


void bud_client_ssl_info_cb(const SSL* ssl, int where, int ret) {
  if ((where & SSL_CB_HANDSHAKE_START) != 0)
    bud_client_handshake_start_cb(ssl);

  if ((where & SSL_CB_HANDSHAKE_DONE) != 0)
    bud_client_handshake_done_cb(ssl);
}


const char* bud_client_get_peer_name(bud_client_t* client) {
  X509* cert;

  cert = SSL_get_peer_certificate(client->ssl);
  if (cert == NULL || cert->name == NULL)
    return NULL;

  /* TODO(indutny): escape them */
  if (strchr(cert->name, '"') != NULL || strchr(cert->name, '\\') != NULL)
    return NULL;

  ASSERT(cert->references > 1, "Certificate couldn't be live for enough time");
  X509_free(cert);
  return cert->name;
}


void bud_client_log(bud_client_t* client,
                    bud_log_level_t level,
                    const char* fmt,
                    ...) {
  va_list pa;

  if (client->close == kBudProgressDone)
    return;

  va_start(pa, fmt);
  bud_clogva(client->config, level, fmt, pa);
  va_end(pa);
}
