#include <string.h>

#include "config/tracing.h"
#include "config.h"
#include "common.h"
#include "logger.h"
#include "master.h"  /* bud_worker_t */

#include "openssl/rand.h"

static bud_error_t bud_config_set_ticket_raw(bud_config_t* config,
                                             uint32_t index,
                                             uint32_t size,
                                             const char* data);


bud_error_t bud_context_set_ticket(bud_context_t* context,
                                   const char* ticket,
                                   size_t size,
                                   bud_encoding_t enc) {
  bud_config_t* config;
  bud_context_t* root;
  size_t max_len;
  int i;

  config = context->config;
  root = &config->contexts[0];

  if (enc == kBudEncodingRaw) {
    if (size != sizeof(context->ticket_key_storage))
      return bud_error(kBudErrSmallTicketKey);

    memcpy(context->ticket_key_storage, ticket, size);
  } else {
    ASSERT(enc == kBudEncodingBase64, "Unexpected encoding of ticket key");

    max_len = sizeof(context->ticket_key_storage);
    if (bud_base64_decode(context->ticket_key_storage,
                          max_len,
                          ticket,
                          size) < max_len) {
      return bud_error(kBudErrSmallTicketKey);
    }
  }

  context->ticket_key_on = 1;
  if (context->ctx != NULL) {
    SSL_CTX_set_tlsext_ticket_keys(context->ctx,
                                   context->ticket_key_storage,
                                   sizeof(context->ticket_key_storage));
  }

  if (context != root)
    return bud_ok();

  /* Update ticket key in dependent contexts */
  for (i = 0; i < config->context_count + 1; i++) {
    bud_context_t* cur;

    cur = &config->contexts[i];
    if (cur->ticket_key_on || cur->ctx == NULL)
      continue;

    SSL_CTX_set_tlsext_ticket_keys(cur->ctx,
                                   cur->ticket_key_storage,
                                   sizeof(cur->ticket_key_storage));
  }

  return bud_ok();
}


bud_error_t bud_config_set_ticket(bud_config_t* config, bud_ipc_msg_t* msg) {
  uint32_t index;
  uint32_t size;
  const char* data;

  bud_ipc_parse_set_ticket(msg, &index, &data, &size);
  return bud_config_set_ticket_raw(config, index, size, data);
}


bud_error_t bud_config_set_ticket_raw(bud_config_t* config,
                                      uint32_t index,
                                      uint32_t size,
                                      const char* data) {
  bud_error_t err;
  int i;

  err = bud_context_set_ticket(&config->contexts[index],
                               data,
                               size,
                               kBudEncodingRaw);
  if (!bud_is_ok(err))
    return err;


  if (config->is_worker) {
    bud_clog(config,
             kBudLogInfo,
             "Worker updated ticket key for context: %d",
             index);
    return bud_ok();
  }


  /* Retransmit */
  for (i = 0; i < config->worker_count; i++) {
    bud_error_t worker_err;
    if (config->workers[i].state & kBudWorkerStateActive) {
      worker_err = bud_ipc_set_ticket(&config->workers[i].ipc,
                                      index,
                                      data,
                                      size);

      /* Send to everyone anyway */
      if (!bud_is_ok(worker_err))
        err = worker_err;
    }
  }

  if (bud_is_ok(err)) {
    bud_clog(config,
             kBudLogInfo,
             "Master retransmitted ticket key for context: %d",
             index);
  }

  return bud_ok();
}


void bud_context_rotate_cb(uv_timer_t* timer) {
  bud_error_t err;
  bud_context_t* context;
  bud_config_t* config;
  int r;
  uint32_t index;

  context = (bud_context_t*) timer->data;
  config = context->config;

  /* No rotation in workers */
  if (config->is_worker)
    return;

  r = RAND_bytes((unsigned char*) context->ticket_key_storage,
                 sizeof(context->ticket_key_storage));
  ASSERT(r == 1, "Failed to randomize new TLS Ticket Key");

  index = context - config->contexts;

  err = bud_config_set_ticket_raw(config,
                                  index,
                                  sizeof(context->ticket_key_storage),
                                  context->ticket_key_storage);
  if (!bud_is_ok(err))
    bud_error_log(config, kBudLogWarning, err);
}
