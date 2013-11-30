#include <stdlib.h>  /* malloc */
#include <string.h>  /* strlen */

#include "uv.h"
#include "http_parser.h"
#include "ringbuffer.h"
#include "parson.h"

#include "http-pool.h"
#include "common.h"
#include "config.h"
#include "queue.h"

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
  bud_http_request_body_cb,
  bud_http_request_message_complete_cb
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
                                     const char* fmt,
                                     const char* arg,
                                     size_t arg_len,
                                     bud_http_cb cb,
                                     bud_error_t* err) {
  bud_http_request_t* req;
  QUEUE* q;

  if (QUEUE_EMPTY(&pool->pool)) {
    /* Create new request */
    req = bud_http_request_new(pool, err);
    if (!bud_is_ok(*err))
      goto fatal;
  } else {
    /* Reuse existing connection */
    q = QUEUE_HEAD(&pool->pool);
    QUEUE_REMOVE(q);
    req = QUEUE_DATA(q, bud_http_request_t, member);
  }

  req->url = bud_http_request_escape_url(fmt, arg, arg_len, &req->url_len);
  req->cb = cb;
  if (req->url == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_http_request_t url");
    free(req);
    goto fatal;
  }

  /* If reused socket - send request immediately */
  if (req->state == kBudHttpConnected)
    *err = bud_http_request_send(req);

  return req;

fatal:
  return NULL;
}


void bud_http_request_error(bud_http_request_t* request, bud_error_t err) {
  request->state = kBudHttpDisconnected;
  if (!bud_is_ok(err) && request->cb != NULL)
    request->cb(request, err);
  request->cb = NULL;

  uv_close((uv_handle_t*) &request->tcp, bud_http_request_close_cb);
  if (!QUEUE_EMPTY(&request->member))
    QUEUE_REMOVE(&request->member);
}


void bud_http_request_done(bud_http_request_t* request) {
  ASSERT(request->state == kBudHttpRunning, "Done on not running request");
  request->state = kBudHttpConnected;
  request->cb(request, bud_ok());
  request->cb = NULL;

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
  uv_buf_t buf[3];

  ASSERT(req->state == kBudHttpConnected, "Writing to not connected socket");

  req->state = kBudHttpRunning;

  buf[0] = UV_STR_BUF("GET ");
  buf[1] = uv_buf_init(req->url, req->url_len);
  buf[2] = UV_STR_BUF(" HTTP/1.1\r\n\r\n");
  r = uv_write(&req->write,
               (uv_stream_t*) &req->tcp,
               buf,
               ARRAY_SIZE(buf),
               bud_http_request_write_cb);
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

  req = container_of(connect, bud_http_request_t, connect);
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
  char* out;
  size_t len;

  req = container_of(stream, bud_http_request_t, tcp);
  if (nread < 0 && nread != UV_EOF) {
    bud_http_request_error(req, bud_error_num(kBudErrHttpReadCb, nread));
    return;
  }

  if (nread == UV_EOF) {
    bud_http_request_error(req, bud_ok());
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

  if (req->complete) {
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
      bud_http_request_done(req);
    }
  }

  if (!http_should_keep_alive(&req->parser))
    bud_http_request_error(req, bud_ok());
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
  req->url = NULL;
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
          url[j++] = c >> 4;
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
