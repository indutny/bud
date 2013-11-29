#include <stdlib.h>  /* calloc, free, NULL */

#include "uv.h"
#include "hiredis/async.h"
#include "hiredis/adapters/libuv.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "redis.h"
#include "common.h"
#include "config.h"
#include "logger.h"
#include "error.h"
#include "queue.h"

/* Flags */
static const int kSniRunning = 0x1;
static const int kSniCanceled = 0x2;

static void bud_redis_close_cb(uv_handle_t* handle);
static bud_error_t bud_redis_connect(bud_redis_t* redis);
static void bud_redis_reconnect(bud_redis_t* redis);
static void bud_redis_connect_cb(const redisAsyncContext* ctx, int status);
static void bud_redis_disconnect_cb(const redisAsyncContext* ctx, int status);
static void bud_redis_timer_cb(uv_timer_t* handle, int status);
static void bud_redis_execute_sni(bud_redis_sni_t* sni);
static void bud_redis_execute_sni_cb(redisAsyncContext* ctx,
                                     void* reply,
                                     void* arg);
static int SSL_CTX_use_certificate_chain(SSL_CTX *ctx, BIO *in);

bud_redis_t* bud_redis_new(bud_config_t* config, bud_error_t* err) {
  bud_redis_t* res;
  int r;

  res = calloc(1, sizeof(*res));
  if (res == NULL)
    goto fatal;
  res->config = config;

  ASSERT(config->redis.enabled, "bud_redis_new() without enabled redis");
  QUEUE_INIT(&res->sni_queue);

  r = uv_timer_init(config->loop, &res->timer);
  if (r != 0) {
    *err = bud_error_num(kBudErrRedisTimerInit, r);
    goto failed_timer_init;
  }

  *err = bud_redis_connect(res);
  if (!bud_is_ok(*err))
    goto failed_connect;

  return res;

failed_connect:
  uv_close((uv_handle_t*) &res->timer, bud_redis_close_cb);
  return NULL;

failed_timer_init:
  free(res);

fatal:
  return NULL;
}


void bud_redis_free(bud_redis_t* redis) {
  redis->ctx->data = NULL;
  redisAsyncDisconnect(redis->ctx);
  redis->ctx = NULL;
  uv_close((uv_handle_t*) &redis->timer, bud_redis_close_cb);
}


bud_redis_sni_t* bud_redis_sni(bud_redis_t* redis,
                               const char* servername,
                               size_t servername_len,
                               bud_redis_sni_cb cb,
                               void* data,
                               bud_error_t* err) {
  bud_redis_sni_t* req;

  req = malloc(sizeof(*req));
  if (req == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_redis_sni_t");
    return NULL;
  }

  /* Add request to the linked list */
  req->redis = redis;
  req->flags = 0;
  req->servername = servername;
  req->servername_len = servername_len;
  req->cb = cb;
  req->data = data;
  QUEUE_INSERT_TAIL(&redis->sni_queue, &req->member);

  /* No connection yet, defer request */
  if (redis->ctx == NULL)
    goto done;

  /* Execute request immediately */
  bud_redis_execute_sni(req);
  return req;

done:
  *err = bud_ok();
  return req;
}


void bud_redis_sni_close(bud_redis_t* redis, bud_redis_sni_t* req) {
  req->flags |= kSniCanceled;
  if (!(req->flags & kSniRunning))
    free(req);
  QUEUE_REMOVE(&req->member);
}


void bud_redis_close_cb(uv_handle_t* handle) {
  bud_redis_t* redis;

  redis = container_of(handle, bud_redis_t, timer);
  free(redis);
}


bud_error_t bud_redis_connect(bud_redis_t* redis) {
  bud_error_t err;
  bud_config_t* config;
  int r;

  config = redis->config;

  redis->ctx = redisAsyncConnect(config->redis.host, config->redis.port);
  if (redis->ctx == NULL) {
    err = bud_error(kBudErrRedisConnect);
    goto fatal;
  }

  r = redisLibuvAttach(redis->ctx, config->loop);
  if (r != 0) {
    err = bud_error_num(kBudErrRedisAttach, r);
    goto failed_attach;
  }
  r = redisAsyncSetConnectCallback(redis->ctx, bud_redis_connect_cb);
  if (r == 0)
    r = redisAsyncSetDisconnectCallback(redis->ctx, bud_redis_disconnect_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrRedisSetCallback, r);
    goto failed_attach;
  }
  redis->ctx->data = redis;

  return bud_ok();

failed_attach:
  redisAsyncDisconnect(redis->ctx);
  redis->ctx = NULL;

fatal:
  return err;
}


void bud_redis_connect_cb(const redisAsyncContext* ctx, int status) {
  bud_redis_t* redis;
  QUEUE* q;

  redis = ctx->data;

  /* Connection failure */
  if (status != 0) {
    /* Already reported */
    if (redis == NULL)
      return;
    bud_log(redis->config,
            kBudLogWarning,
            "Failed to connect to redis: %d (%s)",
            status,
            ctx->errstr);
    return bud_redis_reconnect(redis);
  }

  bud_log(redis->config, kBudLogNotice, "Connected to redis");

  /* Run all pendings requests */
  QUEUE_FOREACH(q, &redis->sni_queue) {
    bud_redis_execute_sni(QUEUE_DATA(q, bud_redis_sni_t, member));
  }
}


void bud_redis_disconnect_cb(const redisAsyncContext* ctx, int status) {
  bud_redis_t* redis;

  /* Disconnected due to termination */
  if (status == REDIS_OK)
    return;

  redis = ctx->data;
  bud_log(redis->config,
          kBudLogWarning,
          "Disconnected from redis: %d (%s)",
          status,
          ctx->errstr);
  bud_redis_reconnect(redis);
}


void bud_redis_reconnect(bud_redis_t* redis) {
  int r;
  bud_config_t* config;

  config = redis->config;

  redis->ctx = NULL;

  r = uv_timer_start(&redis->timer,
                     bud_redis_timer_cb,
                     config->redis.reconnect_timeout,
                     0);
  ASSERT(r == 0, "Failed to start redis reconnect timer");
}


void bud_redis_timer_cb(uv_timer_t* handle, int status) {
  bud_redis_t* redis;
  bud_error_t err;
  ASSERT(status == 0 || status == UV_ECANCELED, "Reconnect timer cb failed");

  /* Deallocating */
  if (status == UV_ECANCELED)
    return;

  redis = container_of(handle, bud_redis_t, timer);

  bud_log(redis->config,
          kBudLogWarning,
          "Reconnecting to redis...");

  err = bud_redis_connect(redis);
  if (!bud_is_ok(err)) {
    bud_error_log(redis->config, kBudLogWarning, err);
    bud_redis_reconnect(redis);
  }
}


void bud_redis_execute_sni(bud_redis_sni_t* sni) {
  int r;
  bud_config_t* config;

  config = sni->redis->config;

  r = redisAsyncCommand(sni->redis->ctx,
                        bud_redis_execute_sni_cb,
                        sni,
                        config->redis.query_fmt,
                        sni->servername,
                        (int) sni->servername_len);
  if (r != 0) {
    QUEUE_REMOVE(&sni->member);
    sni->cb(sni, bud_error_str(kBudErrRedisCmd, sni->redis->ctx->errstr));
    return;
  }

  sni->flags |= kSniRunning;
}

/**
 * NOTE: From node.js
 *
 * Read a file that contains our certificate in "PEM" format,
 * possibly followed by a sequence of CA certificates that should be
 * sent to the peer in the Certificate message.
 *
 * Taken from OpenSSL - editted for style.
 */
int SSL_CTX_use_certificate_chain(SSL_CTX *ctx, BIO *in) {
  int ret;
  X509 *x;
  X509 *ca;
  int r;
  unsigned long err;

  ERR_clear_error();

  ret = 0;
  x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);

  if (x == NULL) {
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);

  if (ERR_peek_error() != 0) {
    /* Key/certificate mismatch doesn't imply ret==0 ... */
    ret = 0;
  }

  if (ret) {
    /**
     * If we could set up our certificate, now proceed to
     * the CA certificates.
     */
    if (ctx->extra_certs != NULL) {
      sk_X509_pop_free(ctx->extra_certs, X509_free);
      ctx->extra_certs = NULL;
    }

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
      r = SSL_CTX_add_extra_chain_cert(ctx, ca);

      if (!r) {
        X509_free(ca);
        ret = 0;
        goto end;
      }
      /**
       * Note that we must not free r if it was successfully
       * added to the chain (while we must free the main
       * certificate, since its reference count is increased
       * by SSL_CTX_use_certificate).
       */
    }

    /* When the while loop ends, it's usually just EOF. */
    err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
        ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
      ERR_clear_error();
    } else  {
      /* some real error */
      ret = 0;
    }
  }

 end:
  if (x != NULL)
    X509_free(x);
  return ret;
}


void bud_redis_execute_sni_cb(redisAsyncContext* ctx, void* reply, void* arg) {
  int r;
  redisReply* rep;
  JSON_Value* json;
  JSON_Object* obj;
  const char* cert_str;
  const char* key_str;
  bud_redis_sni_t* sni;
  bud_redis_t* redis;
  bud_error_t err;
  BIO* bio;
  EVP_PKEY* key;

  sni = arg;
  redis = sni->redis;
  rep = reply;
  sni->flags &= ~kSniRunning;
  if (sni->flags & kSniCanceled) {
    free(sni);
    return;
  }

  /* Disconnected, try running request later */
  if (redis->ctx == NULL)
    return;

  json = NULL;
  sni->sni = NULL;

  /* Success or error */
  QUEUE_REMOVE(&sni->member);
  if (rep->type == REDIS_REPLY_NIL) {
    /* Not found */
    err = bud_ok();
    sni->sni = NULL;
    goto fatal;
  } else if (rep->type != REDIS_REPLY_STRING) {
    err = bud_error_str(kBudErrRedisCmdCb, "Not string reply");
    goto fatal;
  }

  json = json_parse_string(rep->str);
  obj = json_value_get_object(json);
  cert_str = json_object_get_string(obj, "cert");
  key_str = json_object_get_string(obj, "key");
  if (json == NULL || obj == NULL || cert_str == NULL || key_str == NULL) {
    err = bud_error_str(kBudErrJSONParse, "<redis>");
    goto fatal;
  }

  sni->sni = malloc(sizeof(*sni->sni));
  if (sni->sni == NULL) {
    err = bud_error_str(kBudErrNoMem, "SNI bud_context_t");
    goto fatal;
  }

  /* Load NPN from response */
  sni->sni->servername = NULL;
  sni->sni->servername_len = 0;
  sni->sni->ciphers = json_object_get_string(obj, "ciphers");
  sni->sni->npn = json_object_get_array(obj, "npn");

  err = bud_config_new_ssl_ctx(redis->config, sni->sni);
  if (!bud_is_ok(err))
    goto failed_alloc;

  bio = BIO_new_mem_buf((void*) cert_str, strlen(cert_str));
  if (bio == NULL) {
    err = bud_error_str(kBudErrNoMem, "BIO_new_mem_buf");
    goto failed_alloc;
  }

  r = SSL_CTX_use_certificate_chain(sni->sni->ctx, bio);
  BIO_free_all(bio);
  if (!r) {
    err = bud_error_str(kBudErrParseCert, "<redis>");
    goto failed_alloc;
  }

  bio = BIO_new_mem_buf((void*) key_str, strlen(key_str));
  if (bio == NULL) {
    err = bud_error_str(kBudErrNoMem, "BIO_new_mem_buf");
    goto failed_alloc;
  }

  key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if (key == NULL) {
    err = bud_error_str(kBudErrNoMem, "EVP_PKEY");
    goto failed_alloc;
  }

  r = SSL_CTX_use_PrivateKey(sni->sni->ctx, key);
  EVP_PKEY_free(key);
  if (!r) {
    err = bud_error_str(kBudErrParseKey, "<redis>");
    goto failed_alloc;
  }

  err = bud_ok();

failed_alloc:
  if (!bud_is_ok(err)) {
    SSL_CTX_free(sni->sni->ctx);
    free(sni->sni);
    sni->sni = NULL;
  }

fatal:
  sni->cb(sni, err);
  if (sni->sni != NULL)
    sni->sni->npn = NULL;
  free(sni);
  if (json != NULL)
    json_value_free(json);
}
