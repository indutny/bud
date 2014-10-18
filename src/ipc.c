#include <stdlib.h>  /* malloc, free, NULL */

#include "uv.h"

#include "ipc.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "logger.h"

typedef struct bud_ipc_msg_handle_s bud_ipc_msg_handle_t;

struct bud_ipc_msg_handle_s {
  bud_ipc_t* ipc;
  uv_tcp_t tcp;
  uv_write_t req;
};

static void bud_ipc_alloc_cb(uv_handle_t* handle,
                             size_t suggested_size,
                             uv_buf_t* buf);
static void bud_ipc_read_cb(uv_stream_t* stream,
                            ssize_t nread,
                            const uv_buf_t* buf);
static void bud_ipc_parse(bud_ipc_t* ipc);
static void bud_ipc_msg_handle_on_close(uv_handle_t* handle);
static void bud_ipc_msg_send_cb(uv_write_t* req, int status);


bud_error_t bud_ipc_init(bud_ipc_t* ipc, bud_config_t* config) {
  int r;
  bud_error_t err;

  ringbuffer_init(&ipc->buffer);

  ipc->handle = malloc(sizeof(*ipc->handle));
  if (ipc->handle == NULL) {
    err = bud_error_str(kBudErrNoMem, "ipc->handle");
    goto failed_alloc_handle;
  }

  r = uv_pipe_init(config->loop, ipc->handle, 1);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCPipeInit, r);
    goto failed_pipe_init;
  }

  ipc->handle->data = ipc;
  ipc->config = config;
  ipc->state = kBudIPCType;
  ipc->waiting = 1;
  ipc->client_cb = NULL;

  return bud_ok();

failed_pipe_init:
  free(ipc);

failed_alloc_handle:
  return err;
}


bud_error_t bud_ipc_open(bud_ipc_t* ipc, uv_file file) {
  int r;

  r = uv_pipe_open(ipc->handle, file);
  if (r != 0)
    return bud_error_num(kBudErrIPCPipeOpen, r);

  return bud_ok();
}


bud_error_t bud_ipc_start(bud_ipc_t* ipc) {
  int r;

  r = uv_read_start((uv_stream_t*) ipc->handle,
                    bud_ipc_alloc_cb,
                    bud_ipc_read_cb);
  if (r != 0)
    return bud_error_num(kBudErrIPCReadStart, r);

  return bud_ok();
}


void bud_ipc_close(bud_ipc_t* ipc) {
  ringbuffer_destroy(&ipc->buffer);
  if (ipc->handle != NULL)
    uv_close((uv_handle_t*) ipc->handle, (uv_close_cb) free);
  ipc->handle = NULL;
}


void bud_ipc_alloc_cb(uv_handle_t* handle,
                      size_t suggested_size,
                      uv_buf_t* buf) {
  bud_ipc_t* ipc;
  size_t avail;
  char* ptr;

  ipc = handle->data;

  avail = 0;
  ptr = ringbuffer_write_ptr(&ipc->buffer, &avail);
  *buf = uv_buf_init(ptr, avail);
}


void bud_ipc_read_cb(uv_stream_t* stream,
                     ssize_t nread,
                     const uv_buf_t* buf) {
  bud_ipc_t* ipc;
  int r;

  /* This should not really happen */
  ASSERT(nread != UV_EOF, "Unexpected EOF on ipc pipe");
  ipc = stream->data;

  /* Error, must close the stream */
  if (nread < 0) {
    uv_close((uv_handle_t*) ipc->handle, (uv_close_cb) free);
    ipc->handle = NULL;
    /* XXX Report error */
    return;
  }

  r = ringbuffer_write_append(&ipc->buffer, nread);

  /* It is just easier to fail here, and not much point in handling it */
  ASSERT(r >= 0, "Unexpected allocation failure in IPC ring buffer");

  bud_ipc_parse(ipc);

  /* Accept handles */
  while (uv_pipe_pending_count(ipc->handle) > 0) {
    uv_handle_type pending;

    pending = uv_pipe_pending_type(ipc->handle);
    if (pending == UV_UNKNOWN_HANDLE)
      continue;

    ASSERT(pending == UV_TCP, "received non-tcp handle on ipc");
    bud_clog(ipc->config, kBudLogDebug, "received handle on ipc");

    ASSERT(ipc->client_cb != NULL, "ipc client_cb not initialized");
    ipc->client_cb(ipc);
  }
}


void bud_ipc_parse(bud_ipc_t* ipc) {
  /* Loop while there is some data to parse */
  while (ringbuffer_size(&ipc->buffer) >= ipc->waiting) {
    switch (ipc->state) {
      case kBudIPCType:
        {
          uint8_t type;
          size_t len;

          len = 1;
          type = *(uint8_t*) ringbuffer_read_next(&ipc->buffer, &len);
          ASSERT(len >= 1, "Expected at least one byte");

          /* Consume Balance byte */
          if (type == kBudIPCBalance) {
            ringbuffer_read_skip(&ipc->buffer, 1);
            continue;
          }

          /* Wait for full header */
          ipc->waiting = BUD_IPC_HEADER_SIZE;
          ipc->state = kBudIPCHeader;
        }
        break;
      case kBudIPCHeader:
        break;
      case kBudIPCBody:
        break;
    }
  }
}


bud_error_t bud_ipc_balance(bud_ipc_t* ipc, uv_stream_t* server) {
  bud_error_t err;
  int r;
  uint8_t type;
  uv_buf_t buf;
  bud_ipc_msg_handle_t* handle;

  /* Allocate space for a IPC write request */
  handle = malloc(sizeof(*handle));
  if (handle == NULL) {
    err = bud_error_str(kBudErrNoMem, "bud_ipc_msg_handle_t");
    goto failed_malloc;
  }

  handle->ipc = ipc;

  r = uv_tcp_init(ipc->config->loop, &handle->tcp);
  if (r != 0) {
    err = bud_error(kBudErrIPCBalanceInit);
    goto failed_tcp_init;
  }

  /* Accept handle */
  r = uv_accept(server, (uv_stream_t*) &handle->tcp);
  if (r != 0) {
    err = bud_error(kBudErrIPCBalanceAccept);
    goto failed_accept;
  }

  /* Init IPC message */
  type = kBudIPCBalance;
  buf = uv_buf_init((char*) &type, sizeof(type));

  r = uv_write2(&handle->req,
                (uv_stream_t*) ipc->handle,
                &buf,
                1,
                (uv_stream_t*) &handle->tcp,
                bud_ipc_msg_send_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCBalanceWrite, r);
    goto failed_accept;
  }

  return bud_ok();

failed_accept:
  uv_close((uv_handle_t*) &handle->tcp, bud_ipc_msg_handle_on_close);
  return err;

failed_tcp_init:
  free(handle);

failed_malloc:
  return err;
}


void bud_ipc_msg_handle_on_close(uv_handle_t* handle) {
  bud_ipc_msg_handle_t* msg;

  msg = container_of(handle, bud_ipc_msg_handle_t, tcp);
  free(msg);
}


void bud_ipc_msg_send_cb(uv_write_t* req, int status) {
  bud_ipc_msg_handle_t* msg;

  msg = container_of(req, bud_ipc_msg_handle_t, req);
  uv_close((uv_handle_t*) &msg->tcp, bud_ipc_msg_handle_on_close);

  /* Ignore ECANCELED */
  if (status == UV_ECANCELED)
    return;

  /* Error */
  if (status != 0) {
    /* XXX Probably report to caller? */
    bud_clog(msg->ipc->config,
             kBudLogWarning,
             "ipc send_cb() failed with (%d) \"%s\"",
             status,
             uv_strerror(status));
  }
}


uv_stream_t* bud_ipc_get_stream(bud_ipc_t* ipc) {
  ASSERT(ipc->handle != NULL, "IPC get stream before init");
  return (uv_stream_t*) ipc->handle;
}
