#include "uv.h"

#include "avail.h"
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
