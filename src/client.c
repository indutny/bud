#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>

#include "uv.h"
#include "bio.h"
#include "ringbuffer.h"
#include "openssl/bio.h"

#include "common.h"
#include "client.h"
#include "logger.h"

typedef enum bud_side_e bud_side_t;

enum bud_side_e {
  kBudFrontend,
  kBudBackend
};

static void bud_client_close(bud_client_t* client, bud_side_t error_side);
static void bud_client_close_cb(uv_handle_t* handle);
static void bud_client_alloc_cb(uv_handle_t* handle,
                                size_t suggested_size,
                                uv_buf_t* buf);
static void bud_client_read_cb(uv_stream_t* stream,
                               ssize_t nread,
                               const uv_buf_t* buf);
static void bud_client_cycle(bud_client_t* client);
static void bud_client_clear_in(bud_client_t* client);
static void bud_client_clear_out(bud_client_t* client);
static void bud_client_send(bud_client_t* client, uv_tcp_t* tcp);
static void bud_client_send_cb(uv_write_t* req, int status);
static void bud_client_connect_cb(uv_connect_t* req, int status);
static int bud_client_shutdown(bud_client_t* client, bud_side_t side);
static int bud_client_prepend_proxyline(bud_client_t* client);
static void bud_client_log(bud_client_t* client,
                           bud_side_t side,
                           const char* fmt,
                           int code,
                           const char* reason);
static void bud_client_debug(bud_client_t* client,
                             bud_side_t side,
                             const char* fmt,
                             int code);
static const char* bud_sslerror_str(int err);
static const char* bud_side_str(bud_side_t side);


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
  client->tcp_in.data = client;
  client->tcp_out.data = client;
  client->destroying = 0;
  client->shutdown = 0;
  client->destroy_waiting = 0;
  client->current_enc_write = 0;
  client->current_clear_write = 0;
  client->current_enc_waiting = 0;
  client->current_clear_waiting = 0;

  /* Initialize buffers */
  ringbuffer_init(&client->enc_in);
  ringbuffer_init(&client->enc_out);
  ringbuffer_init(&client->clear_in);
  ringbuffer_init(&client->clear_out);

  /**
   * Accept client on frontend
   */
  r = uv_tcp_init(config->loop, &client->tcp_in);
  if (r != 0)
    goto failed_tcp_in_init;

  r = uv_accept(stream, (uv_stream_t*) &client->tcp_in);
  if (r != 0)
    goto failed_accept;

  r = uv_read_start((uv_stream_t*) &client->tcp_in,
                    bud_client_alloc_cb,
                    bud_client_read_cb);
  if (r != 0)
    goto failed_accept;

  /*
   * Connect to backend
   * NOTE: We won't start reading until some SSL data will be sent.
   */
  r = uv_tcp_init(config->loop, &client->tcp_out);
  if (r != 0)
    goto failed_accept;

  r = uv_tcp_connect(&client->connect_req,
                     &client->tcp_out,
                     (struct sockaddr*) &client->config->backend.addr,
                     bud_client_connect_cb);
  if (r != 0)
    goto failed_connect;

  /* Adjust sockets */
  r = uv_tcp_nodelay(&client->tcp_in, 1);
  if (r == 0)
    r = uv_tcp_nodelay(&client->tcp_out, 1);
  if (r == 0 && config->frontend.keepalive > 0)
    r = uv_tcp_keepalive(&client->tcp_in, 1, config->frontend.keepalive);
  if (r == 0 && config->backend.keepalive > 0)
    r = uv_tcp_keepalive(&client->tcp_out, 1, config->backend.keepalive);
  if (r != 0)
    goto failed_connect;

  /* Initialize SSL */

  /* First context is always default */
  client->ssl = SSL_new(config->contexts[0].ctx);
  if (client->ssl == NULL)
    goto failed_connect;

  enc_in = bud_bio_new(&client->enc_in);
  if (enc_in == NULL)
    goto failed_connect;
  enc_out = bud_bio_new(&client->enc_out);
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

  return;

failed_connect:
  client->destroy_waiting++;
  uv_close((uv_handle_t*) &client->tcp_out, bud_client_close_cb);

failed_accept:
  client->destroy_waiting++;
  uv_close((uv_handle_t*) &client->tcp_in, bud_client_close_cb);
  return;

failed_tcp_in_init:
  free(client);
}


void bud_client_close(bud_client_t* client, bud_side_t error_side) {
  if (client->destroying) {
    /* Force close, even if waiting */
    if (error_side == kBudFrontend && client->current_enc_waiting) {
      uv_close((uv_handle_t*) &client->tcp_in, bud_client_close_cb);
      client->current_enc_waiting = 0;
    }
    if (error_side == kBudBackend && client->current_clear_waiting) {
      uv_close((uv_handle_t*) &client->tcp_out, bud_client_close_cb);
      client->current_clear_waiting = 0;
    }
    return;
  }

  /* Close offending side, and wait for write finish on other side */
  client->destroy_waiting = 2;
  client->destroying = 1;

  if (error_side == kBudBackend && ringbuffer_size(&client->enc_out) != 0)
    client->current_enc_waiting = 1;
  else
    uv_close((uv_handle_t*) &client->tcp_in, bud_client_close_cb);

  if (error_side == kBudFrontend && ringbuffer_size(&client->clear_out) != 0)
    client->current_clear_waiting = 1;
  else
    uv_close((uv_handle_t*) &client->tcp_out, bud_client_close_cb);
}


void bud_client_close_cb(uv_handle_t* handle) {
  bud_client_t* client;

  client = (bud_client_t*) handle->data;

  if (--client->destroy_waiting != 0)
    return;

  ringbuffer_destroy(&client->enc_in);
  ringbuffer_destroy(&client->enc_out);
  ringbuffer_destroy(&client->clear_in);
  ringbuffer_destroy(&client->clear_out);

  SSL_free(client->ssl);
  client->ssl = NULL;
  free(client);
}


void bud_client_alloc_cb(uv_handle_t* handle,
                         size_t suggested_size,
                         uv_buf_t* buf) {
  bud_client_t* client;
  ssize_t avail;
  char* ptr;
  ringbuffer* buffer;

  client = handle->data;

  if (handle == (uv_handle_t*) &client->tcp_in)
    buffer = &client->enc_in;
  else
    buffer = &client->clear_in;

  avail = 0;
  ptr = ringbuffer_write_ptr(buffer, &avail);
  *buf = uv_buf_init(ptr, avail);
}


void bud_client_read_cb(uv_stream_t* stream,
                        ssize_t nread,
                        const uv_buf_t* buf) {
  int r;
  bud_client_t* client;
  ringbuffer* buffer;
  bud_side_t side;

  client = stream->data;

  if (stream == (uv_stream_t*) &client->tcp_in) {
    side = kBudFrontend;
    buffer = &client->enc_in;
  } else {
    side = kBudBackend;
    buffer = &client->clear_in;

    /* Try writing close_notify */
    if (nread == UV_EOF)
      bud_client_shutdown(client, kBudFrontend);
  }
  bud_client_debug(client,
                   side,
                   "client read_cb() = %d on %s",
                   nread);

  /* Commit data if there was no error */
  if (nread >= 0)
    r = ringbuffer_write_append(buffer, nread);
  if (nread < 0 || r != 0) {
    /* Write out all data, before closing socket */
    bud_client_cycle(client);

    if (nread < 0) {
      if (nread != UV_EOF) {
        bud_client_log(client,
                       side,
                       "client read_cb failed with (%d) \"%s\" on %s",
                       nread,
                       uv_strerror(nread));
      }
    } else {
      bud_client_log(client,
                     side,
                     "client write_append failed with (%d) \"%s\" on %s",
                     r,
                     NULL);
    }
    return bud_client_close(client, side);
  }

  /* If buffer is full - stop reading */
  if (ringbuffer_is_full(buffer)) {
    bud_client_debug(client,
                     side,
                     "client throttle (%d) on %s",
                     ringbuffer_size(buffer));
    r = uv_read_stop(stream);
    if (r != 0) {
      bud_client_log(client,
                     side,
                     "client read_stop failed with (%d) \"%s\" on %s",
                     r,
                     uv_strerror(r));
      return bud_client_close(client, side);
    }
  }

  bud_client_cycle(client);
}


void bud_client_cycle(bud_client_t* client) {
  bud_client_clear_in(client);
  bud_client_clear_out(client);
  bud_client_send(client, &client->tcp_in);
  bud_client_send(client, &client->tcp_out);
}


void bud_client_clear_in(bud_client_t* client) {
  char* data;
  ssize_t size;
  int written;
  int err;

  written = 0;
  while (!ringbuffer_is_empty(&client->clear_in)) {
    data = ringbuffer_read_next(&client->clear_in, &size);
    written = SSL_write(client->ssl, data, size);
    if (written < 0)
      break;

    ASSERT(written == size, "SSL_write() did unexpected partial write");
    ringbuffer_read_skip(&client->clear_in, written);
  }

  if (written >= 0)
    return;

  err = SSL_get_error(client->ssl, written);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return;

  bud_client_log(client,
                 kBudFrontend,
                 "client SSL_write failed with (%d) \"%s\" on %s",
                 err,
                 bud_sslerror_str(err));
  bud_client_close(client, kBudFrontend);
}


void bud_client_clear_out(bud_client_t* client) {
  int read;
  int err;
  ssize_t avail;
  char* out;

  /* If buffer is full - stop reading */
  if (ringbuffer_is_full(&client->clear_out)) {
    bud_client_debug(client,
                     kBudBackend,
                     "client throttle (%d) on %s",
                     ringbuffer_size(&client->clear_out));

    err = uv_read_stop((uv_stream_t*) &client->tcp_in);
    if (err != 0) {
      bud_client_log(client,
                     kBudBackend,
                     "client read_stop_failed failed with (%d) \"%s\" on %s",
                     err,
                     uv_strerror(err));
      return bud_client_close(client, kBudBackend);
    }

    return;
  }

  do {
    avail = 0;
    out = ringbuffer_write_ptr(&client->clear_out, &avail);
    read = SSL_read(client->ssl, out, avail);
    if (read > 0) {
      ringbuffer_write_append(&client->clear_out, read);
      bud_client_send(client, &client->tcp_out);
    }
  } while (read > 0);

  if (read > 0)
    return;

  err = SSL_get_error(client->ssl, read);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return;

  bud_client_log(client,
                 kBudFrontend,
                 "client SSL_read failed with (%d) \"%s\"",
                 err,
                 bud_sslerror_str(err));
  bud_client_close(client, kBudFrontend);
}


void bud_client_send(bud_client_t* client, uv_tcp_t* tcp) {
  uv_write_t* req;
  bud_side_t side;
  ringbuffer* buffer;
  ssize_t* size;;
  char* out;
  uv_buf_t buf;
  int r;

  if (tcp == &client->tcp_in) {
    side = kBudFrontend;
    req = &client->enc_write_req;
    buffer = &client->enc_out;
    size = &client->current_enc_write;
  } else {
    side = kBudBackend;
    req = &client->clear_write_req;
    buffer = &client->clear_out;
    size = &client->current_clear_write;
  }

  /* Already writing */
  if (*size != 0)
    return;

  /* Try writing close_notify */
  if (client->destroying)
    bud_client_shutdown(client, side);

  out = ringbuffer_read_next(buffer, size);
  if (*size == 0)
      return;
  bud_client_debug(client,
                   side,
                   "client write(%d) on %s",
                   *size);

  buf = uv_buf_init(out, *size);
  req->data = client;
  r = uv_write(req, (uv_stream_t*) tcp, &buf, 1, bud_client_send_cb);

  if (r == 0)
    return;

  bud_client_log(client,
                 side,
                 "client uv_write() failed with (%d) \"%s\" on %s",
                 r,
                 uv_strerror(r));
  bud_client_close(client, side);
}


void bud_client_send_cb(uv_write_t* req, int status) {
  int r;
  bud_side_t side;
  bud_client_t* client;
  ringbuffer* buffer;
  ssize_t* size;
  int waiting;
  uv_tcp_t* current;
  uv_stream_t* opposite;

  client = req->data;

  if (req == &client->enc_write_req) {
    side = kBudFrontend;
    buffer = &client->enc_out;
    size = &client->current_enc_write;
    waiting = client->current_enc_waiting;
    current = &client->tcp_in;
    opposite = (uv_stream_t*) &client->tcp_out;
  } else {
    side = kBudBackend;
    buffer = &client->clear_out;
    size = &client->current_clear_write;
    waiting = client->current_clear_waiting;
    current = &client->tcp_out;
    opposite = (uv_stream_t*) &client->tcp_in;
  }

  if (status != 0) {
    bud_client_log(client,
                   side,
                   "client uv_write() cb failed with (%d) \"%s\" on %s",
                   status,
                   uv_strerror(status));
    return bud_client_close(client, side);
  }

  /* Start reading, if stopped */
  if (!waiting) {
    bud_client_debug(client,
                     side,
                     "client read_start (%d) on opposite of: %s",
                     0);
    r = uv_read_start(opposite, bud_client_alloc_cb, bud_client_read_cb);
    if (r != 0) {
      side = side == kBudFrontend ? kBudBackend : kBudFrontend;
      bud_client_log(client,
                     side,
                     "client uv_read_start() failed with (%d) \"%s\" on %s",
                     r,
                     uv_strerror(r));
      return bud_client_close(client, side);
    }
  }

  /* Consume written data */
  ringbuffer_read_skip(buffer, *size);
  *size = 0;

  /* In the destroy, but writing data */
  if (waiting) {
    ASSERT(client->destroying, "Waiting, but client not destroying");

    /* Cycle again */
    bud_client_cycle(client);

    /* No new data, destroy */
    if (ringbuffer_size(buffer) == 0)
      bud_client_close(client, side);
    return;
  }
}


void bud_client_connect_cb(uv_connect_t* req, int status) {
  bud_client_t* client;

  client = container_of(req, bud_client_t, connect_req);
  bud_client_debug(client,
                   kBudBackend,
                   "client backend connect %d on %s",
                   status);

  if (status != 0 && status != UV_ECANCELED) {
    bud_client_log(client,
                   kBudBackend,
                   "client uv_connect() failed with (%d) \"%s\" on %s",
                   status,
                   uv_strerror(status));
    return bud_client_close(client, kBudBackend);
  }

  /* Do nothing, we will start reading once handshake will be performed */
}


int bud_client_shutdown(bud_client_t* client, bud_side_t side) {
  if (client->shutdown || side != kBudFrontend)
    return -1;

  client->shutdown = 1;
  if (SSL_shutdown(client->ssl) == 0)
    SSL_shutdown(client->ssl);

  return 0;
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
  r = uv_tcp_getpeername(&client->tcp_in,
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

  return (int) ringbuffer_write_into(&client->clear_in, proxyline, r);
}


const char* bud_side_str(bud_side_t side) {
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
                    bud_side_t side,
                    const char* fmt,
                    int code,
                    const char* reason) {
  if (client->destroying)
    return;
  bud_log(client->config,
          side == kBudBackend ? kBudLogWarning : kBudLogNotice,
          (char*) fmt,
          code,
          reason,
          bud_side_str(side));
}


void bud_client_debug(bud_client_t* client,
                      bud_side_t side,
                      const char* fmt,
                      int code) {
  bud_log(client->config,
          kBudLogDebug,
          (char*) fmt,
          code,
          bud_side_str(side));
}
