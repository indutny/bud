#include "uv.h"

#include "avail.h"
#include "client.h"
#include "client-common.h"
#include "config.h"
#include "logger.h"

static void bud_kill_backend(bud_config_t* config,
                             bud_config_backend_t* backend);
static void bud_revive_backend(uv_timer_t* timer, int status);

bud_config_backend_t* bud_select_backend(bud_config_t* config) {
  bud_config_backend_t* res;
  int first;
  uint64_t now;
  uint64_t death_timeout;

  now = uv_now(config->loop);
  death_timeout = (uint64_t) config->availability.death_timeout;

  first = config->last_backend;
  do {
    res = &config->backend[config->last_backend];

    /*
     * Mark backend as dead if it isn't responding for a significant
     * amount of time
     */
    if (!res->dead && res->dead_since != 0) {
      if (now - res->last_checked < death_timeout &&
          now - res->dead_since > death_timeout) {
        bud_kill_backend(config, res);
      }
    }

    config->last_backend++;
    config->last_backend %= config->backend_count;
  } while (res->dead && config->last_backend != first);

  /* All dead.
   * Make sure we make progress when selecting backends.
   */
  if (res->dead) {
    res = &config->backend[config->last_backend];
    config->last_backend++;
    config->last_backend %= config->backend_count;
  }

  return res;
}


void bud_kill_backend(bud_config_t* config,
                      bud_config_backend_t* backend) {
  int r;

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


  bud_log(config,
          kBudLogWarning,
          "Killed backend %s:%d",
          backend->host,
          backend->port);
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


void bud_revive_backend(uv_timer_t* timer, int status) {
  bud_config_backend_t* backend;

  if (status == UV_ECANCELED)
    return;

  /* Ignore errors */
  backend = timer->data;
  backend->dead = 0;
  backend->dead_since = 0;
  uv_close((uv_handle_t*) backend->revive_timer, (uv_close_cb) free);
  backend->revive_timer = NULL;

  bud_log(backend->config,
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
    client->destroy_waiting--;
    uv_close((uv_handle_t*) &client->backend.tcp, bud_client_connect_close_cb);
    client->backend.close = kBudProgressDone;
    return;
  }

  /* Success */
  client->connect = kBudProgressDone;

  /* Start reading if queued */
  if (client->backend.reading == kBudProgressRunning) {
    cerr = bud_client_read_start(client, &client->backend);
    if (!bud_is_ok(cerr.err))
      return bud_client_close(client, cerr);
  }

  /* Cycle data anyway */
  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    return bud_client_close(client, cerr);
}


void bud_client_connect_close_cb(uv_handle_t* handle) {
  bud_client_error_t cerr;
  bud_client_t* client;

  client = handle->data;

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

  if (++client->retry_count > client->config->availability.max_retries) {
    WARNING_LN(&client->backend, "Retried too many times");
    return bud_client_error(bud_error(kBudErrMaxRetries), side);
  }

  /* Select backend again */
  client->backend.close = kBudProgressDone;
  client->selected_backend = bud_select_backend(client->config);

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


void bud_client_retry_cb(uv_timer_t* timer, int status) {
  bud_client_error_t cerr;
  bud_client_t* client;

  if (status == UV_ECANCELED)
    return;

  client = timer->data;
  client->retry = kBudProgressDone;

  /* Backend still dead, try again */
  if (client->selected_backend->dead) {
    cerr = bud_client_retry(client);
    if (!bud_is_ok(cerr.err))
      bud_client_close(client, cerr);
    return;
  }

  if (status != 0) {
    return bud_client_close(
        client,
        bud_client_error(bud_error_num(kBudErrClientRetry, status),
                         &client->backend));
  }

  cerr = bud_client_connect(client);
  if (!bud_is_ok(cerr.err))
    bud_client_close(client, cerr);
}
