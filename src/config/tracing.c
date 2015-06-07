#include <stdlib.h>

#include "config/tracing.h"
#include "config.h"
#include "common.h"

#include "parson.h"

#define BUD_CONFIG_INIT_TRACING(V) trace->V = NULL;

#define BUD_CONFIG_ALLOC_TRACING(V)                                           \
    trace->V = calloc(trace->dso_count + 1, sizeof(*trace->V));               \
    if (trace->V == NULL)                                                     \
      goto fatal;                                                             \

#define BUD_CONFIG_FREE_TRACING(V)                                            \
    free(trace->V);                                                           \
    trace->V = NULL;                                                          \


bud_error_t bud_config_load_tracing(bud_config_trace_t* trace,
                                JSON_Object* obj) {
  BUD_TRACING_ENUM(BUD_CONFIG_INIT_TRACING)

  trace->dso_count = 0;
  trace->dso = NULL;
  trace->dso_array = NULL;

  if (obj == NULL)
    return bud_ok();

  trace->dso_array = json_object_get_array(obj, "dso");
  trace->dso_count = json_array_get_count(trace->dso_array);
  if (trace->dso_count == 0)
    goto done;

  trace->dso = calloc(trace->dso_count, sizeof(*trace->dso));
  if (trace->dso == NULL)
    return bud_error_str(kBudErrNoMem, "trace dso");

  BUD_TRACING_ENUM(BUD_CONFIG_ALLOC_TRACING)

done:
  return bud_ok();

fatal:
  BUD_TRACING_ENUM(BUD_CONFIG_FREE_TRACING)
  free(trace->dso);
  trace->dso = NULL;

  return bud_error_str(kBudErrNoMem, "trace callbacks");
}


#undef BUD_CONFIG_FREE_TRACING
#undef BUD_CONFIG_ALLOC_TRACING
#undef BUD_CONFIG_INIT_TRACING


#define BUD_CONFIG_DECL_CLIENT_TRACING(V) bud_trace_cb_t* last_##V;
#define BUD_CONFIG_DECL_BACKEND_TRACING(V) bud_trace_backend_cb_t* last_##V;
#define BUD_CONFIG_DECL_CLOSE_TRACING(V) bud_trace_close_cb_t* last_##V;

#define BUD_CONFIG_INIT_TRACING(V) last_##V = trace->V;

#define BUD_CONFIG_COPY_TRACING(V)                                            \
    if (module->V != NULL) {                                                  \
      *last_##V = module->V;                                                  \
      last_##V++;                                                             \
    }                                                                         \

#define BUD_CONFIG_ZERO_TRACING(V)                                            \
    if (last_##V == trace->V) {                                               \
      free(trace->V);                                                         \
      trace->V = NULL;                                                        \
    }                                                                         \

bud_error_t bud_config_init_tracing(bud_config_trace_t* trace) {
  int i;
  int r;
  bud_error_t err;
  BUD_TRACING_CLIENT_ENUM(BUD_CONFIG_DECL_CLIENT_TRACING)
  BUD_TRACING_BACKEND_ENUM(BUD_CONFIG_DECL_BACKEND_TRACING)
  BUD_TRACING_CLOSE_ENUM(BUD_CONFIG_DECL_CLOSE_TRACING)

  BUD_TRACING_ENUM(BUD_CONFIG_INIT_TRACING)

  for (i = 0; i < trace->dso_count; i++) {
    bud_trace_module_t* module;

    r = uv_dlopen(json_array_get_string(trace->dso_array, i), &trace->dso[i]);
    if (r != 0) {
      i--;
      err = bud_error_num(kBudErrDLOpen, r);
      goto fatal;
    }

    r = uv_dlsym(&trace->dso[i], "bud_trace_module", (void**) &module);
    if (r != 0) {
      err = bud_error_num(kBudErrDLSym, r);
      goto fatal;
    }

    /* Verify that version is correct */
    if (module->version != BUD_TRACE_VERSION) {
      err = bud_error_num(kBudErrDLVersion, module->version);
      goto fatal;
    }

    BUD_TRACING_ENUM(BUD_CONFIG_COPY_TRACING)
  }

  BUD_TRACING_ENUM(BUD_CONFIG_ZERO_TRACING)

  return bud_ok();

fatal:
  /* Unload libraries */
  for (; i >= 0; i--)
    uv_dlclose(&trace->dso[i]);

  /* Prevent us from unloading it again in trace_free */
  trace->dso_count = 0;

  return err;
}


#undef BUD_CONFIG_ZERO_TRACING
#undef BUD_CONFIG_COPY_TRACING
#undef BUD_CONFIG_DECL_CLIENT_TRACING
#undef BUD_CONFIG_DECL_BACKEND_TRACING
#undef BUD_CONFIG_DECL_CLOSE_TRACING
#undef BUD_CONFIG_INIT_TRACING


void bud_config_trace_free(bud_config_trace_t* trace) {
  int i;

  for (i = 0; i < trace->dso_count; i++)
    uv_dlclose(&trace->dso[i]);

  free(trace->dso);
  trace->dso = NULL;
}
