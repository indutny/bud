#include <stdlib.h>  /* malloc, free, NULL */
#include <string.h>  /* memcpy */

#include "uv.h"

#include "src/ipc.h"
#include "src/common.h"
#include "src/config.h"
#include "src/error.h"
#include "src/logger.h"

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
static void bud_ipc_accept_pending(bud_ipc_t* ipc);


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
  /* NOTE: May be overriden by bud_ipc_wait() */
  ipc->ready = kBudIPCReadyDone;
  ipc->client_cb = NULL;
  ipc->msg_cb = NULL;

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

  bud_ipc_parse(ipc);
  bud_ipc_accept_pending(ipc);

  r = uv_read_start((uv_stream_t*) ipc->handle,
                    bud_ipc_alloc_cb,
                    bud_ipc_read_cb);
  if (r != 0)
    return bud_error_num(kBudErrIPCReadStart, r);

  return bud_ok();
}


void bud_ipc_close(bud_ipc_t* ipc) {
  if (ipc->handle != NULL) {
    ringbuffer_destroy(&ipc->buffer);
    uv_close((uv_handle_t*) ipc->handle, (uv_close_cb) free);
  }
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

  ipc = stream->data;

  /* This should not really happen */
  if (nread == UV_EOF) {
    bud_ipc_msg_t msg;

    msg.type = kBudIPCEOF;
    msg.size = 0;

    ASSERT(ipc->msg_cb != NULL, "ipc msg_cb not initialized");
    ipc->msg_cb(ipc, &msg);
    return;
  }

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

  /* Accept incoming handles only after loading configuration */
  if (ipc->ready != kBudIPCReadyDone)
    return;

  bud_ipc_accept_pending(ipc);
}


void bud_ipc_accept_pending(bud_ipc_t* ipc) {
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
    /* Accept IPC messages after initialization will finish */
    if (ipc->ready == kBudIPCReadyNextTick)
      break;

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
        {
          size_t r;
          char buf[BUD_IPC_HEADER_SIZE];

          r = ringbuffer_read_into(&ipc->buffer, buf, sizeof(buf));
          ASSERT(r == ipc->waiting, "Read less than expected");

          ipc->pending.type = *(uint8_t*) buf;
          ipc->pending.size = bud_read_uint32(buf, 1);

          ipc->waiting = ipc->pending.size;
          ipc->state = kBudIPCBody;
        }
        break;
      case kBudIPCBody:
        {
          bud_ipc_msg_t* msg;
          size_t r;

          msg = malloc(sizeof(*msg) + ipc->waiting - 1);

          /* Can't read, just skip */
          if (msg == NULL) {
            ringbuffer_read_skip(&ipc->buffer, ipc->waiting);
            continue;
          }

          memcpy(msg, &ipc->pending, sizeof(*msg));
          r = ringbuffer_read_into(&ipc->buffer,
                                   (char*) msg->data,
                                   ipc->waiting);
          ASSERT(r == ipc->waiting, "Read less than expected");

          ASSERT(ipc->msg_cb != NULL, "ipc msg_cb not initialized");
          ipc->msg_cb(ipc, msg);

          ipc->waiting = 1;
          ipc->state = kBudIPCType;
        }
        break;
    }
  }
}


void bud_ipc_wait(bud_ipc_t* ipc) {
  ipc->ready = kBudIPCReadyNone;
  do
    uv_run(ipc->config->loop, UV_RUN_ONCE);
  while (ipc->ready == kBudIPCReadyNone);
  ASSERT(ipc->ready == kBudIPCReadyNextTick, "Unexpected IPC state");
  ipc->ready = kBudIPCReadyDone;
}


void bud_ipc_continue(bud_ipc_t* ipc) {
  ipc->ready = kBudIPCReadyNextTick;
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


bud_error_t bud_ipc_send(bud_ipc_t* ipc,
                         bud_ipc_msg_header_t* header,
                         const char* body) {
  bud_error_t err;
  uv_write_t* req;
  uv_buf_t buf;
  int r;

  /* Allocate space for a IPC write request */
  req = malloc(sizeof(*req) + BUD_IPC_HEADER_SIZE + header->size);
  if (req == NULL) {
    err = bud_error_str(kBudErrNoMem, "uv_write_t (ipc)");
    goto failed_malloc;
  }

  buf = uv_buf_init((char*) req + sizeof(*req),
                    BUD_IPC_HEADER_SIZE + header->size);

  buf.base[0] = header->type;
  bud_write_uint32(buf.base, header->size, 1);
  memcpy(buf.base + BUD_IPC_HEADER_SIZE, body, header->size);

  r = uv_write(req,
               (uv_stream_t*) ipc->handle,
               &buf,
               1,
               (uv_write_cb) free);
  if (r != 0) {
    err = bud_error_num(kBudErrIPCSend, r);
    goto failed_write;
  }

  return bud_ok();

failed_write:
  free(req);

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


void bud_ipc_parse_set_ticket(bud_ipc_msg_t* msg,
                              uint32_t* index,
                              const char** data,
                              uint32_t* size) {
  ASSERT(msg->size >= 4, "Too small message size for Set Ticket");

  *index = bud_read_uint32(msg->data, 0);
  *data = (const char*) msg->data + 4;
  *size = msg->size - 4;
}


bud_error_t bud_ipc_set_ticket(bud_ipc_t* ipc,
                               uint32_t index,
                               const char* data,
                               uint32_t size) {
  bud_ipc_msg_header_t header;
  char storage[64];
  ASSERT(size + 4 <= sizeof(storage), "Too big message for Set Ticket");

  memcpy(storage + 4, data, size);
  bud_write_uint32(storage, index, 0);

  header.type = kBudIPCSetTicket;
  header.size = size + 4;

  return bud_ipc_send(ipc, &header, storage);
}
