#include <stdlib.h>  /* malloc */
#include <string.h>  /* strlen */

#include "uv.h"
#include "http_parser.h"
#include "ringbuffer.h"
#include "parson.h"

#include "src/http-pool.h"
#include "src/common.h"
#include "src/config.h"
#include "src/logger.h"
#include "src/queue.h"

static bud_http_request_t* bud_http_request(bud_http_pool_t* pool,
                                            bud_http_method_t method,
                                            const char* fmt,
                                            const char* arg,
                                            size_t arg_len,
                                            const char* body,
                                            size_t body_len,
                                            bud_http_cb cb,
                                            bud_error_t* err);
static bud_http_request_t* bud_http_request_new(bud_http_pool_t* pool,
                                                bud_error_t* err);
static bud_error_t bud_http_request_send(bud_http_request_t* req);
static void bud_http_request_write_cb(uv_write_t* req, int status);
static void bud_http_request_connect_cb(uv_connect_t* connect, int status);
static void bud_http_request_alloc_cb(uv_handle_t* handle,
                                      size_t suggested_size,
                                      uv_buf_t* buf);
static void bud_http_request_read_cb(uv_stream_t* stream,
                                     ssize_t nread,
                                     const uv_buf_t* buf);
static int bud_http_request_body_cb(http_parser* parser,
                                    const char *at,
                                    size_t length);
static int bud_http_request_message_complete_cb(http_parser* parser);
static void bud_http_request_close_cb(uv_handle_t* handle);
static void bud_http_request_error(bud_http_request_t* request,
                                   bud_error_t err);
static void bud_http_request_done(bud_http_request_t* request);
static char* bud_http_request_escape_url(const char* fmt,
                                         const char* arg,
                                         size_t arg_len,
                                         size_t* size);

static http_parser_settings bud_parser_settings = {
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  bud_http_request_body_cb,
  bud_http_request_message_complete_cb,
  NULL,
  NULL
};

bud_http_pool_t* bud_http_pool_new(bud_config_t* config,
                                   const char* host,
                                   uint16_t port,
                                   bud_error_t* err) {
  bud_http_pool_t* pool;
  int r;

  pool = malloc(sizeof(*pool));
  if (pool == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_http_pool_t");
    goto fatal;
  }

  QUEUE_INIT(&pool->pool);
  QUEUE_INIT(&pool->reqs);

  pool->host_len = strlen(host);
  pool->host = malloc(pool->host_len + 1);
  pool->port = port;
  if (pool->host == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_http_pool_t host");
    goto failed_allocate_host;
  }

  pool->config = config;
  memcpy(pool->host, host, pool->host_len + 1);

  r = bud_config_str_to_addr(pool->host, pool->port, &pool->addr);
  if (r != 0) {
    *err = bud_error_num(kBudErrPton, r);
    goto failed_str_to_addr;
  }

  *err = bud_ok();
  return pool;

failed_str_to_addr:
  free(pool->host);

failed_allocate_host:
  free(pool);

fatal:
  return NULL;
}


void bud_http_pool_free(bud_http_pool_t* pool) {
  QUEUE* q;
  bud_http_request_t* req;

  /* Cancel requests */
  while (!QUEUE_EMPTY(&pool->pool)) {
    q = QUEUE_HEAD(&pool->pool);
    req = QUEUE_DATA(q, bud_http_request_t, member);
    bud_http_request_cancel(req);
    req->pool = NULL;
  }

  while (!QUEUE_EMPTY(&pool->reqs)) {
    q = QUEUE_HEAD(&pool->reqs);
    req = QUEUE_DATA(q, bud_http_request_t, member);
    bud_http_request_cancel(req);
    req->pool = NULL;
  }

  /* Free pool */
  free(pool->host);
  pool->host = NULL;
  free(pool);
}


bud_http_request_t* bud_http_request(bud_http_pool_t* pool,
                                     bud_http_method_t method,
                                     const char* fmt,
                                     const char* arg,
                                     size_t arg_len,
                                     const char* body,
                                     size_t body_len,
                                     bud_http_cb cb,
                                     bud_error_t* err) {
  bud_http_request_t* req;
  char* body_copy;
  char* url;
  size_t url_len;
  QUEUE* q;

  /* Clone body */
  if (body_len != 0) {
    body_copy = malloc(body_len);
    if (body_copy == NULL) {
      *err = bud_error_str(kBudErrNoMem, "body_copy");
      goto fatal;
    }
    memcpy(body_copy, body, body_len);
  } else {
    body_copy = NULL;
  }

  /* Format url */
  url = bud_http_request_escape_url(fmt, arg, arg_len, &url_len);
  if (url == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_http_request_t url");
    goto failed_escape_url;
  }

  /* Obtain request */
  if (QUEUE_EMPTY(&pool->pool)) {
    /* Create new request */
    req = bud_http_request_new(pool, err);
    if (!bud_is_ok(*err))
      goto failed_http_request;

    bud_clog(pool->config, kBudLogDebug, "pool %p new request %p", pool, req);
  } else {
    /* Reuse existing connection */
    q = QUEUE_HEAD(&pool->pool);
    QUEUE_REMOVE(q);
    req = QUEUE_DATA(q, bud_http_request_t, member);

    bud_clog(pool->config, kBudLogDebug, "pool %p reuse request %p", pool, req);
  }

  req->method = method;
  req->url = url;
  req->url_len = url_len;
  req->body = body_copy;
  req->body_len = body_len;
  req->cb = cb;
  req->response = NULL;
  req->code = 0;

  /* If reused socket - send request immediately */
  if (req->state == kBudHttpConnected) {
    *err = bud_http_request_send(req);
    if (!bud_is_ok(*err))
      goto failed_send;
  }

  return req;

failed_send:
  /* Fail without calling cb */
  bud_http_request_error(req, bud_ok());
  return NULL;

failed_http_request:
  free(url);

failed_escape_url:
  free(body_copy);

fatal:
  return NULL;
}


bud_http_request_t* bud_http_get(bud_http_pool_t* pool,
                                 const char* fmt,
                                 const char* arg,
                                 size_t arg_len,
                                 bud_http_cb cb,
                                 bud_error_t* err) {
  return bud_http_request(pool,
                          kBudHttpGet,
                          fmt,
                          arg,
                          arg_len,
                          NULL,
                          0,
                          cb,
                          err);
}


bud_http_request_t* bud_http_post(bud_http_pool_t* pool,
                                  const char* fmt,
                                  const char* arg,
                                  size_t arg_len,
                                  const char* data,
                                  size_t data_len,
                                  bud_http_cb cb,
                                  bud_error_t* err) {
  return bud_http_request(pool,
                          kBudHttpPost,
                          fmt,
                          arg,
                          arg_len,
                          data,
                          data_len,
                          cb,
                          err);
}


void bud_http_request_error(bud_http_request_t* request, bud_error_t err) {
  if (request->state == kBudHttpDisconnected)
    return;

  if (!bud_is_ok(err)) {
    bud_clog(request->pool->config, kBudLogWarning,
             "pool %p request error %p: %s", request->pool, request,
             bud_error_to_str(err));
  }

  request->pool = NULL;
  request->state = kBudHttpDisconnected;
  if (!bud_is_ok(err) && request->cb != NULL) {
    request->cb(request, err);
  }
  request->cb = NULL;

  ASSERT(request->state == kBudHttpDisconnected,
         "Request must be abandoned by user after error");

  uv_close((uv_handle_t*) &request->tcp, bud_http_request_close_cb);
  if (!QUEUE_EMPTY(&request->member))
    QUEUE_REMOVE(&request->member);
}


void bud_http_request_done(bud_http_request_t* request) {
  bud_clog(request->pool->config, kBudLogDebug, "pool %p request done %p",
           request->pool, request);

  ASSERT(request->state == kBudHttpRunning, "Done on not running request");
  request->state = kBudHttpConnected;
  request->cb(request, bud_ok());
  request->cb = NULL;

  ASSERT(request->state == kBudHttpConnected,
         "Request must be abandoned by user after completion");

  /* Remove from reqs */
  ASSERT(!QUEUE_EMPTY(&request->member), "Request should be in queue");
  QUEUE_REMOVE(&request->member);

  /* Add to pool */
  QUEUE_INSERT_TAIL(&request->pool->pool, &request->member);

  /* Clear buffer */
  ringbuffer_destroy(&request->response_buf);
  ringbuffer_init(&request->response_buf);
  request->complete = 0;
}


void bud_http_request_cancel(bud_http_request_t* request) {
  bud_clog(request->pool->config, kBudLogDebug, "pool: request cancel %p",
           request);

  bud_http_request_error(request, bud_ok());
}


bud_http_request_t* bud_http_request_new(bud_http_pool_t* pool,
                                         bud_error_t* err) {
  bud_http_request_t* req;
  int r;

  req = malloc(sizeof(*req));
  if (req == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_http_request_t");
    goto fatal;
  }

  req->pool = pool;
  http_parser_init(&req->parser, HTTP_RESPONSE);
  ringbuffer_init(&req->response_buf);
  req->complete = 0;

  r = uv_tcp_init(pool->config->loop, &req->tcp);
  if (r != 0) {
    *err = bud_error_num(kBudErrHttpTcpInit, r);
    goto failed_tcp_init;
  }

  r = uv_tcp_connect(&req->connect,
                     &req->tcp,
                     (struct sockaddr*) &pool->addr,
                     bud_http_request_connect_cb);
  if (r != 0) {
    *err = bud_error_num(kBudErrHttpTcpConnect, r);
    goto failed_tcp_connect;
  }

  req->state = kBudHttpConnecting;
  QUEUE_INSERT_TAIL(&pool->reqs, &req->member);

  *err = bud_ok();
  return req;

failed_tcp_connect:
  uv_close((uv_handle_t*) &req->tcp, bud_http_request_close_cb);
  return NULL;

failed_tcp_init:
  free(req);

fatal:
  return NULL;
}

#define UV_STR_BUF(str) uv_buf_init((str), sizeof(str) - 1)

bud_error_t bud_http_request_send(bud_http_request_t* req) {
  int r;
  uv_buf_t get_buf[4];
  uv_buf_t post_buf[8];

  ASSERT(req->state == kBudHttpConnected, "Writing to not connected socket");

  req->state = kBudHttpRunning;

  if (req->method == kBudHttpGet) {
    char host[256];

    get_buf[0] = UV_STR_BUF("GET ");
    get_buf[1] = uv_buf_init(req->url, req->url_len);
    get_buf[2] = UV_STR_BUF(" HTTP/1.1\r\nHost: ");
    get_buf[3] = uv_buf_init(host,
                             snprintf(host,
                                      sizeof(host),
                                      "%s:%d\r\n\r\n",
                                      req->pool->host,
                                      req->pool->port));

    r = uv_write(&req->write,
                 (uv_stream_t*) &req->tcp,
                 get_buf,
                 ARRAY_SIZE(get_buf),
                 bud_http_request_write_cb);
  } else {
    char body_length[128];
    char host[256];

    post_buf[0] = UV_STR_BUF("POST ");
    post_buf[1] = uv_buf_init(req->url, req->url_len);
    post_buf[2] = UV_STR_BUF(" HTTP/1.1\r\n"
                             "Content-Type: application/json\r\n"
                             "Host: ");
    post_buf[3] = uv_buf_init(host,
                              snprintf(host,
                                       sizeof(host),
                                       "%s:%d\r\n",
                                       req->pool->host,
                                       req->pool->port));
    post_buf[4] = UV_STR_BUF("Content-Length: ");
    post_buf[5] = uv_buf_init(body_length,
                              snprintf(body_length,
                                       sizeof(body_length),
                                       "%d\r\n\r\n",
                                       (int) req->body_len));
    post_buf[6] = uv_buf_init(req->body, req->body_len);
    post_buf[7] = UV_STR_BUF("\r\n");

    r = uv_write(&req->write,
                 (uv_stream_t*) &req->tcp,
                 post_buf,
                 ARRAY_SIZE(post_buf),
                 bud_http_request_write_cb);
  }
  if (r != 0)
    return bud_error_num(kBudErrHttpWrite, r);

  return bud_ok();
}

#undef UV_STR_BUF

void bud_http_request_write_cb(uv_write_t* write, int status) {
  bud_http_request_t* req;

  if (status == 0 || status == UV_ECANCELED)
    return;

  /* Write failure */
  req = container_of(write, bud_http_request_t, write);
  bud_http_request_error(req, bud_error_num(kBudErrHttpWriteCb, status));
}


void bud_http_request_connect_cb(uv_connect_t* connect, int status) {
  bud_http_request_t* req;
  bud_error_t err;
  int r;

  /* Already handled */
  if (status == UV_ECANCELED)
    return;

  req = container_of(connect, bud_http_request_t, connect);

  ASSERT(req->state == kBudHttpConnecting,
         "Got connect_cb on disconnected http request");

  req->state = kBudHttpConnected;
  if (status != 0) {
    err = bud_error_num(kBudErrHttpConnectCb, status);
    goto fatal;
  }

  /* Start reading */
  r = uv_read_start((uv_stream_t*) &req->tcp,
                    bud_http_request_alloc_cb,
                    bud_http_request_read_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrHttpReadStart, r);
    goto fatal;
  }

  /* Send request */
  err = bud_http_request_send(req);
  if (!bud_is_ok(err))
    goto fatal;
  return;

fatal:
  bud_http_request_error(req, err);
  return;
}


void bud_http_request_alloc_cb(uv_handle_t* handle,
                               size_t suggested_size,
                               uv_buf_t* buf) {
  bud_http_request_t* req;

  req = container_of(handle, bud_http_request_t, tcp);

  *buf = uv_buf_init(req->buf, sizeof(req->buf));
}


void bud_http_request_read_cb(uv_stream_t* stream,
                              ssize_t nread,
                              const uv_buf_t* buf) {
  bud_http_request_t* req;
  size_t parsed;

  req = container_of(stream, bud_http_request_t, tcp);
  if (nread < 0 && nread != UV_EOF) {
    bud_http_request_error(req, bud_error_num(kBudErrHttpReadCb, nread));
    return;
  }

  if (nread == UV_EOF) {
    bud_http_request_error(req, bud_error(kBudErrHttpEof));
    return;
  }

  /* Parse all read data */
  parsed = http_parser_execute(&req->parser,
                               &bud_parser_settings,
                               req->buf,
                               (size_t) nread);
  if (parsed != (size_t) nread) {
    bud_http_request_error(
        req,
        bud_error_str(kBudErrHttpParse,
                      http_errno_description(HTTP_PARSER_ERRNO(&req->parser))));
    return;
  }

  if (!req->complete)
    return;

  char* out;
  size_t len;

  len = ringbuffer_size(&req->response_buf);
  out = malloc(len + 1);
  if (out == NULL) {
    bud_http_request_error(req, bud_error_str(kBudErrNoMem, "http response"));
    return;
  }

  ringbuffer_read_into(&req->response_buf, out, len);
  out[len] = 0;
  req->code = req->parser.status_code;
  req->response = json_parse_string(out);
  free(out);
  if (req->response == NULL) {
    bud_http_request_error(req,
                           bud_error_str(kBudErrJSONParse, "http response"));
  } else {
    /* Emit the callback */
    bud_http_request_done(req);

    /* Unqueue request from the pool, if it can't be reused */
    if (!http_should_keep_alive(&req->parser))
      bud_http_request_error(req, bud_ok());
  }
}


int bud_http_request_body_cb(http_parser* parser,
                             const char *at,
                             size_t length) {
  size_t r;
  bud_http_request_t* req;

  req = container_of(parser, bud_http_request_t, parser);
  r = ringbuffer_write_into(&req->response_buf, at, length);

  if (r != 0)
    return -1;

  return 0;
}


static int bud_http_request_message_complete_cb(http_parser* parser) {
  bud_http_request_t* req;

  req = container_of(parser, bud_http_request_t, parser);
  req->complete = 1;

  return 0;
}


void bud_http_request_close_cb(uv_handle_t* handle) {
  bud_http_request_t* req;

  req = container_of(handle, bud_http_request_t, tcp);
  ringbuffer_destroy(&req->response_buf);
  free(req->url);
  free(req->body);
  req->url = NULL;
  req->body = NULL;
  free(req);
}


char* bud_http_request_escape_url(const char* fmt,
                                  const char* arg,
                                  size_t arg_len,
                                  size_t* size) {
  char* url;
  size_t fmt_len;
  size_t i;
  size_t j;
  size_t k;
  size_t escaped_arg_len;
  char c;

  /* Escape arg */
  fmt_len = strlen(fmt);

  /* Count characters in escaped arg */
  escaped_arg_len = 0;
  for (i = 0; i < arg_len; i++) {
    c = arg[i];

    if (c == '!' || c == '#' || c == '$' || c == '&' || c == '\'' ||
        c == '(' || c == ')' || c == '*' || c == '+' || c == ',' ||
        c == '/' || c == ':' || c == ';' || c == '=' || c == '?' ||
        c == '@' || c == '[' || c == ']') {
      escaped_arg_len += 3;
    } else {
      escaped_arg_len++;
    }
  }

  url = malloc(fmt_len + escaped_arg_len + 1);
  if (url == NULL)
    return NULL;

  k = 0;
  for (i = 0, j = 0; i < fmt_len; i++) {
    /* Replace '%s' with escaped arg */
    if (k == 0 && i + 1 < fmt_len && fmt[i] == '%' && fmt[i + 1] == 's') {
      for (k = 0; k < arg_len; k++) {
        c = arg[k];
        if (c == '!' || c == '#' || c == '$' || c == '&' || c == '\'' ||
            c == '(' || c == ')' || c == '*' || c == '+' || c == ',' ||
            c == '/' || c == ':' || c == ';' || c == '=' || c == '?' ||
            c == '@' || c == '[' || c == ']') {
          url[j++] = '%';
          url[j++] = '0' + (c >> 4);
          c = c & 15;
          if (c > 9)
            c = 'a' + c - 10;
          else
            c = '0' + c;
        }
        url[j++] = c;
      }
      /* Skip second part of '%s' */
      i++;
    } else {
      url[j++] = fmt[i];
    }
  }
  url[j] = '\0';
  ASSERT(j < fmt_len + escaped_arg_len + 1, "http request url OOB");

  *size = j;
  return url;
}
