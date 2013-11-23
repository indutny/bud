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
static void bud_client_clear_out(bud_client_t* client);
static void bud_client_send(bud_client_t* client, uv_tcp_t* tcp);
static void bud_client_send_cb(uv_write_t* req, int status);


void bud_client_create(bud_server_t* server) {
  int r;
  bud_client_t* client;
  BIO* enc_in;
  BIO* enc_out;
#ifdef SSL_MODE_RELEASE_BUFFERS
  long mode;
#endif  /* SSL_MODE_RELEASE_BUFFERS */

  client = calloc(1, sizeof(*client));
  if (client == NULL)
    return;

  r = uv_tcp_init(server->tcp.loop, &client->tcp_in);
  if (r != 0)
    goto failed_tcp_init;

  r = uv_accept((uv_stream_t*) &server->tcp, (uv_stream_t*) &client->tcp_in);
  if (r != 0)
    goto failed_accept;

  r = uv_read_start((uv_stream_t*) &client->tcp_in,
                    bud_client_alloc_cb,
                    bud_client_read_cb);
  if (r != 0)
    goto failed_accept;

  /* Initialize buffers and SSL */
  ringbuffer_init(&client->enc_in);
  ringbuffer_init(&client->enc_out);
  ringbuffer_init(&client->clear_out);

  client->ssl = SSL_new(server->config->contexts[0].ctx);
  if (client->ssl == NULL)
    goto failed_accept;

  enc_in = bud_bio_new(&client->enc_in);
  if (enc_in == NULL)
    goto failed_accept;
  enc_out = bud_bio_new(&client->enc_out);
  if (enc_out == NULL) {
    BIO_free_all(enc_in);
    goto failed_accept;
  }
  SSL_set_bio(client->ssl, enc_in, enc_out);

#ifdef SSL_MODE_RELEASE_BUFFERS
  mode = SSL_get_mode(client->ssl);
  SSL_set_mode(client->ssl, mode | SSL_MODE_RELEASE_BUFFERS);
#endif  /* SSL_MODE_RELEASE_BUFFERS */

  SSL_set_accept_state(client->ssl);

  /* TODO(indutny): connect to backend */

  return;

failed_accept:
  uv_close((uv_handle_t*) &client->tcp_in, bud_client_close_cb);
  return;

failed_tcp_init:
  free(client);
}


void bud_client_destroy(bud_client_t* client) {
  if (client->destroying)
    return;

  client->destroying = 1;
  uv_close((uv_handle_t*) &client->tcp_in, bud_client_close_cb);
}


void bud_client_close_cb(uv_handle_t* handle) {
  bud_client_t* client;

  client = container_of(handle, bud_client_t, tcp_in);

  ringbuffer_destroy(&client->enc_in);
  ringbuffer_destroy(&client->enc_out);
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

  client = container_of(handle, bud_client_t, tcp_in);

  avail = 0;
  ptr = ringbuffer_write_ptr(&client->enc_in, &avail);
  *buf = uv_buf_init(ptr, avail);
}


void bud_client_read_cb(uv_stream_t* stream,
                        ssize_t nread,
                        const uv_buf_t* buf) {
  bud_client_t* client;

  client = container_of(stream, bud_client_t, tcp_in);

  /* Commit data if there was no error */
  if (nread < 0 ||
      ringbuffer_write_append(&client->enc_in, nread) != 0) {
    /* Write out all data, before closing socket */
    bud_client_clear_out(client);

    /* TODO(indutny): log cause */
    return bud_client_destroy(client);
  }

  bud_client_cycle(client);
}


void bud_client_cycle(bud_client_t* client) {
  bud_client_clear_out(client);
  bud_client_send(client, &client->tcp_in);
}


void bud_client_clear_out(bud_client_t* client) {
  int read;
  int err;
  ssize_t avail;
  char* out;

  do {
    avail = 0;
    out = ringbuffer_write_ptr(&client->clear_out, &avail);
    read = SSL_read(client->ssl, out, avail);
    if (read > 0) {
      ringbuffer_write_append(&client->clear_out, read);
      // bud_client_send(client, &client->tcp_out);
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
  buf = uv_buf_init(out, *size);
  req->data = client;
  r = uv_write(req, (uv_stream_t*) tcp, &buf, 1, bud_client_send_cb);

  /* TODO(indutny): log cause */
  if (r != 0)
    bud_client_destroy(client);
}


void bud_client_send_cb(uv_write_t* req, int status) {
  bud_client_t* client;
  ringbuffer* buffer;
  ssize_t* size;

  client = req->data;

  /* TODO(indutny): log cause */
  if (status != 0)
    return bud_client_destroy(client);

  if (req == &client->enc_write_req) {
    buffer = &client->enc_out;
    size = &client->current_enc_write;
  } else {
    buffer = &client->clear_out;
    size = &client->current_clear_write;
  }

  /* Consume written data */
  ringbuffer_read_skip(buffer, *size);
  *size = 0;
}
