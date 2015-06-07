#include "uv.h"

#include "src/avail.h"
#include "src/client.h"
#include "src/client-common.h"
#include "src/common.h"
#include "src/config.h"
#include "src/logger.h"
#include "src/tracing.h"

static void bud_kill_backend(bud_client_t* client,
                             bud_config_backend_t* backend);
static void bud_revive_backend(uv_timer_t* timer);

bud_config_backend_t* bud_select_backend(bud_client_t* client) {
  bud_config_t* config;
  bud_config_balance_t balance;
  bud_config_backend_list_t* backend;
  bud_config_backend_t* res;
  int first;
  uint64_t now;
  uint64_t death_timeout;

  config = client->config;
  balance = client->balance;
  backend = client->backend_list;

  /* External balancing if any of backends has `external` field */
  if (backend->external_count != 0) {
    char key[1024];
    unsigned int key_len;

    /* Lookup in external map */
    key_len = snprintf(key,
                       sizeof(key),
                       "[%.*s]:%d",
                       client->local.host_len,
                       client->local.host,
                       config->frontend.port);
    res = bud_hashmap_get(&backend->external_map, key, key_len);
    if (res != NULL) {
      backend->last = res - backend->list;

      /* Info for tracing */
      client->balance = kBudBalanceExternal;
    }

    /* Continue with default balancing */
  }

  now = uv_now(config->loop);
  death_timeout = (uint64_t) config->availability.death_timeout;

  /* Always try the top-most backend when balancing `on-fail` */
  if (balance == kBudBalanceOnFail)
    backend->last = 0;

  first = backend->last;
  do {
    res = &backend->list[backend->last];

    /*
     * Mark backend as dead if it isn't responding for a significant
     * amount of time
     */
    if (!res->dead && res->dead_since != 0) {
      if (now - res->last_checked <= death_timeout &&
          now - res->dead_since >= death_timeout) {
        bud_kill_backend(client, res);
      }
    }

    /* Do not iterate over backends when balancing 'on-fail' */
    if (balance == kBudBalanceOnFail && !res->dead)
      break;

    backend->last++;
    backend->last %= backend->count;
  } while (res->dead && backend->last != first);

  /* All dead.
   * Make sure we make progress when selecting backends.
   */
  if (res->dead) {
    res = &backend->list[backend->last];
    backend->last++;
    backend->last %= backend->count;
  }

  return res;
}


void bud_kill_backend(bud_client_t* client,
                      bud_config_backend_t* backend) {
  bud_config_t* config;
  int r;

  config = client->config;

  /* If there're no reviving - there are no death */
  if (config->availability.revive_interval == 0)
    return;

  /* Already waiting for revival */
  if (backend->revive_timer != NULL)
    return;

  backend->revive_timer = malloc(sizeof(*backend->revive_timer));
  if (backend->revive_timer == NULL)
    return;

  r = uv_timer_init(config->loop, backend->revive_timer);
  if (r != 0)
    goto failed_init;
  backend->revive_timer->data = backend;
  r = uv_timer_start(backend->revive_timer,
                     bud_revive_backend,
                     config->availability.revive_interval,
                     0);
  if (r != 0)
    goto failed_start;


  bud_clog(config,
           kBudLogWarning,
           "Killed backend %s:%d",
           backend->host,
           backend->port);
  bud_trace_kill_backend(client, backend);
  backend->dead = 1;
  return;

failed_start:
  uv_close((uv_handle_t*) backend->revive_timer, (uv_close_cb) free);
  backend->revive_timer = NULL;
  return;

failed_init:
  free(backend->revive_timer);
  backend->revive_timer = NULL;
}


void bud_revive_backend(uv_timer_t* timer) {
  bud_config_backend_t* backend;

  /* Ignore errors */
  backend = timer->data;
  uv_close((uv_handle_t*) backend->revive_timer, (uv_close_cb) free);

  /* Backend is gone :( */
  if (backend == NULL)
    return;

  backend->dead = 0;
  backend->dead_since = 0;
  backend->revive_timer = NULL;

  bud_trace_revive_backend(NULL, backend);
  bud_clog(backend->config,
           kBudLogWarning,
           "Reviving backend %s:%d",
           backend->host,
           backend->port);
}


bud_client_error_t bud_client_connect(bud_client_t* client) {
  int r;
  bud_config_t* config;
  bud_config_backend_t* backend;

  config = client->config;
  backend = client->selected_backend;

  /*
   * Connect to backend
   * NOTE: We won't start reading until some SSL data will be sent.
   */
  r = uv_tcp_init(config->loop, &client->backend.tcp);
  if (r != 0)
    goto fatal;
  client->backend.close = client->close;
  client->destroy_waiting++;

  if (r == 0)
    r = uv_tcp_nodelay(&client->backend.tcp, 1);
  if (r == 0 && backend->keepalive > 0)
    r = uv_tcp_keepalive(&client->backend.tcp, 1, backend->keepalive);
  if (r != 0)
    goto failed_connect;

  DBG(&client->backend, "connecting to %s:%d", backend->host, backend->port);

  r = uv_tcp_connect(&client->connect_req,
                     &client->backend.tcp,
                     (struct sockaddr*) &backend->addr,
                     bud_client_connect_cb);
  if (r != 0)
    goto failed_connect;

  client->connect = kBudProgressRunning;

  return bud_client_ok(&client->backend);

failed_connect:
  uv_close((uv_handle_t*) &client->backend.tcp, bud_client_close_cb);
  client->backend.close = kBudProgressDone;

  return bud_client_error(bud_error_num(kBudErrClientConnect, r),
                          &client->backend);

fatal:
  return bud_client_error(bud_error_num(kBudErrClientConnect, r),
                          &client->backend);
}


void bud_client_connect_cb(uv_connect_t* req, int status) {
  bud_client_t* client;
  bud_client_error_t cerr;

  if (status == UV_ECANCELED)
    return;

  client = container_of(req, bud_client_t, connect_req);
  DBG(&client->backend, "connect %d", status);

  client->selected_backend->last_checked = uv_now(client->config->loop);

  if (status != 0) {
    /* Error, try reconnecting */
    client->connect = kBudProgressNone;
    WARNING(&client->backend,
            "uv_connect() failed: %d - \"%s\"",
            status,
            uv_strerror(status));
    if (client->selected_backend->dead_since == 0)
      client->selected_backend->dead_since = uv_now(client->config->loop);

    /* But reopen the socket first */
    uv_close((uv_handle_t*) &client->backend.tcp, bud_client_connect_close_cb);
    client->backend.close = kBudProgressDone;
    return;
  }

  /* Success */
  client->connect = kBudProgressDone;
  client->selected_backend->dead_since = 0;
  bud_trace_backend_connect(client, client->selected_backend);

  /* Start reading if queued */
  if (client->backend.reading == kBudProgressRunning) {
    cerr = bud_client_read_start(client, &client->backend);
    if (!bud_is_ok(cerr.err))
      goto fatal;
  }

  /* Prepend proxyline if configured any */
  cerr = bud_client_prepend_proxyline(client);
  if (!bud_is_ok(cerr.err))
    goto fatal;

  /* Cycle data anyway */
  cerr = bud_client_cycle(client);
  if (bud_is_ok(cerr.err))
    return;

fatal:
  bud_client_close(client, cerr);
}


void bud_client_connect_close_cb(uv_handle_t* handle) {
  bud_client_error_t cerr;
  bud_client_t* client;

  client = handle->data;
  if (client->close != kBudProgressNone)
    return bud_client_close_cb(handle);

  client->destroy_waiting++;
  cerr = bud_client_retry(client);
  if (bud_is_ok(cerr.err))
    return;

  bud_client_close(client, cerr);
}


bud_client_error_t bud_client_retry(bud_client_t* client) {
  int r;
  bud_client_side_t* side;

  side = &client->backend;

  /* Client closing can't retry */
  if (client->close != kBudProgressNone)
    return bud_client_error(bud_error(kBudErrRetryAfterClose), side);

  if (++client->retry_count > client->config->availability.max_retries)
    return bud_client_error(bud_error(kBudErrMaxRetries), side);

  /* Select backend again */
  client->backend.close = kBudProgressDone;
  if (client->backend_list != NULL)
    client->selected_backend = bud_select_backend(client);

  client->retry = kBudProgressNone;
  r = uv_timer_start(&client->retry_timer,
                     bud_client_retry_cb,
                     client->config->availability.retry_interval,
                     0);
  if (r != 0)
    return bud_client_error(bud_error_num(kBudErrRetryTimerStart, r), side);
  client->retry = kBudProgressRunning;

  return bud_client_ok();
}


void bud_client_retry_cb(uv_timer_t* timer) {
  bud_client_error_t cerr;
  bud_client_t* client;

  client = timer->data;
  client->retry = kBudProgressDone;

  /* Backend still dead, try again */
  if (client->selected_backend->dead) {
    WARNING_LN(&client->backend, "backend still dead, retrying");
    bud_trace_retry(client);
    cerr = bud_client_retry(client);
    if (!bud_is_ok(cerr.err))
      bud_client_close(client, cerr);
    return;
  }

  cerr = bud_client_connect(client);
  if (!bud_is_ok(cerr.err))
    bud_client_close(client, cerr);
}
