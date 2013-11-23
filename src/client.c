#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>

#include "uv.h"
#include "bio.h"
#include "ringbuffer.h"
#include "openssl/bio.h"

#include "common.h"
#include "client.h"

static void bud_client_destroy(bud_client_t* client);
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
static int bud_client_prepend_proxyline(bud_client_t* client);


void bud_client_create(bud_server_t* server) {
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

  client->server = server;
  client->tcp_in.data = client;
  client->tcp_out.data = client;
  client->destroying = 0;
  client->destroy_waiting = 0;
  client->current_enc_write = 0;
  client->current_clear_write = 0;

  /**
   * Accept client on frontend
   */
  r = uv_tcp_init(server->tcp.loop, &client->tcp_in);
  if (r != 0)
    goto failed_tcp_in_init;

  r = uv_accept((uv_stream_t*) &server->tcp, (uv_stream_t*) &client->tcp_in);
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
  r = uv_tcp_init(server->tcp.loop, &client->tcp_out);
  if (r != 0)
    goto failed_accept;

  r = uv_tcp_connect(&client->connect_req,
                     &client->tcp_out,
                     (struct sockaddr*) &client->server->backend,
                     bud_client_connect_cb);
  if (r != 0)
    goto failed_connect;

  /* Initialize buffers and SSL */
  ringbuffer_init(&client->enc_in);
  ringbuffer_init(&client->enc_out);
  ringbuffer_init(&client->clear_in);
  ringbuffer_init(&client->clear_out);

  /* First context is always default */
  client->ssl = SSL_new(server->config->contexts[0].ctx);
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

  if (server->config->frontend.proxyline) {
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


void bud_client_destroy(bud_client_t* client) {
  if (client->destroying)
    return;

  client->destroy_waiting = 2;
  client->destroying = 1;
  uv_close((uv_handle_t*) &client->tcp_in, bud_client_close_cb);
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
  bud_client_t* client;
  ringbuffer* buffer;

  client = stream->data;

  if (stream == (uv_stream_t*) &client->tcp_in) {
    buffer = &client->enc_in;

    /* Try writing close_notify */
    if (nread == UV_EOF)
      SSL_shutdown(client->ssl);
  } else {
    buffer = &client->clear_in;
  }

  /* Commit data if there was no error */
  if (nread < 0 || ringbuffer_write_append(buffer, nread) != 0) {
    /* Write out all data, before closing socket */
    bud_client_clear_out(client);
    bud_client_send(client, &client->tcp_in);

    /* TODO(indutny): log cause */
    return bud_client_destroy(client);
  }

  /* If buffer is full - stop reading */
  if (ringbuffer_is_full(buffer)) {
    /* TODO(indutny): log cause */
    if (uv_read_stop(stream) != 0)
      return bud_client_destroy(client);
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

  /* TODO(indutny): log cause */
  bud_client_destroy(client);
}


void bud_client_clear_out(bud_client_t* client) {
  int read;
  int err;
  ssize_t avail;
  char* out;

  /* If buffer is full - stop reading */
  if (ringbuffer_is_full(&client->clear_out)) {
    /* TODO(indutny): log cause */
    if (uv_read_stop((uv_stream_t*) &client->tcp_in) != 0)
      return bud_client_destroy(client);

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

  /* TODO(indutny): log cause */
  bud_client_destroy(client);
}


void bud_client_send(bud_client_t* client, uv_tcp_t* tcp) {
  uv_write_t* req;
  ringbuffer* buffer;
  ssize_t* size;
  char* out;
  uv_buf_t buf;
  int r;

  if (tcp == &client->tcp_in) {
    req = &client->enc_write_req;
    buffer = &client->enc_out;
    size = &client->current_enc_write;
  } else {
    req = &client->clear_write_req;
    buffer = &client->clear_out;
    size = &client->current_clear_write;
  }

  /* Already writing */
  if (*size != 0)
    return;

  out = ringbuffer_read_next(buffer, size);
  if (*size == 0)
    return;

  buf = uv_buf_init(out, *size);
  req->data = client;
  r = uv_write(req, (uv_stream_t*) tcp, &buf, 1, bud_client_send_cb);

  /* TODO(indutny): log cause */
  if (r != 0)
    bud_client_destroy(client);
}


void bud_client_send_cb(uv_write_t* req, int status) {
  int r;
  bud_client_t* client;
  ringbuffer* buffer;
  ssize_t* size;
  uv_stream_t* opposite;

  client = req->data;

  /* TODO(indutny): log cause */
  if (status != 0)
    return bud_client_destroy(client);

  if (req == &client->enc_write_req) {
    buffer = &client->enc_out;
    size = &client->current_enc_write;
    opposite = (uv_stream_t*) &client->tcp_out;
  } else {
    buffer = &client->clear_out;
    size = &client->current_clear_write;
    opposite = (uv_stream_t*) &client->tcp_in;
  }

  /* Start reading, if stopped */
  r = uv_read_start(opposite, bud_client_alloc_cb, bud_client_read_cb);
  /* TODO(indutny): log cause */
  if (r != 0)
    return bud_client_destroy(client);

  /* Consume written data */
  ringbuffer_read_skip(buffer, *size);
  *size = 0;
}


void bud_client_connect_cb(uv_connect_t* req, int status) {
  bud_client_t* client;

  client = container_of(req, bud_client_t, connect_req);

  /* TODO(indutny): log cause */
  if (status != 0)
    return bud_client_destroy(client);

  /* Do nothing, we will start reading once handshake will be performed */
}


int bud_client_prepend_proxyline(bud_client_t* client) {
  int r;
  struct sockaddr_storage storage;
  int storage_size;
  struct sockaddr_in* addr;
  struct sockaddr_in6* addr6;
  const char* family;
  char host[INET6_ADDRSTRLEN];
  char proxyline[256];

  storage_size = sizeof(storage);
  r = uv_tcp_getpeername(&client->tcp_in,
                         (struct sockaddr*) &storage,
                         &storage_size);
  if (r != 0)
    return r;

  addr = (struct sockaddr_in*) &storage;
  if (addr->sin_family == AF_INET) {
    family = "TCP4";
    r = uv_inet_ntop(AF_INET, &addr->sin_addr, host, sizeof(host));
  } else if (addr->sin_family == AF_INET6) {
    family = "TCP6";
    addr6 = (struct sockaddr_in6*) &addr;
    r = uv_inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
  } else {
    return -1;
  }

  if (r != 0)
    return r;

  r = snprintf(proxyline,
               sizeof(proxyline),
               client->server->proxyline_fmt,
               family,
               host,
               ntohs(addr->sin_port));
  ASSERT(r < (int) sizeof(proxyline), "Client proxyline overflow");

  return (int) ringbuffer_write_into(&client->clear_in, proxyline, r);
}
