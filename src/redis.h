#ifndef SRC_REDIS_H_
#define SRC_REDIS_H_

#include "uv.h"
#include "hiredis/async.h"

#include "config.h"
#include "error.h"
#include "queue.h"

/* Forward declaration */
struct bud_redis_sni_s;

typedef struct bud_redis_s bud_redis_t;
typedef struct bud_redis_sni_s bud_redis_sni_t;
typedef void (*bud_redis_sni_cb)(bud_redis_sni_t* sni, bud_error_t status);

struct bud_redis_s {
  bud_config_t* config;
  QUEUE sni_queue;
  redisAsyncContext* ctx;

  uv_timer_t timer;
};

struct bud_redis_sni_s {
  QUEUE member;

  bud_redis_t* redis;
  int flags;
  const char* servername;
  size_t servername_len;
  bud_redis_sni_cb cb;
  void* data;

  bud_context_t* sni;
};


bud_redis_t* bud_redis_new(bud_config_t* config, bud_error_t* err);
void bud_redis_free(bud_redis_t* redis);
bud_redis_sni_t* bud_redis_sni(bud_redis_t* redis,
                               const char* servername,
                               size_t servername_len,
                               bud_redis_sni_cb cb,
                               void* data,
                               bud_error_t* err);
void bud_redis_sni_close(bud_redis_t* redis, bud_redis_sni_t* req);

#endif  /* SRC_REDIS_H_ */
