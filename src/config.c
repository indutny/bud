#include <getopt.h>  /* getopt */
#include <stdio.h>  /* fprintf */
#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset, strlen, strncmp */
#include <strings.h>  /* strcasecmp */

#include "uv.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "parson.h"

#include "src/config.h"
#include "src/config/files.h"
#include "src/config/ticket.h"
#include "src/config/tracing.h"
#include "src/config/ocsp.h"
#include "src/config/utils.h"
#include "src/client.h"
#include "src/client-common.h"
#include "src/common.h"
#include "src/ocsp.h"
#include "src/http-pool.h"
#include "src/logger.h"
#include "src/master.h"  /* bud_worker_t */
#include "src/version.h"

static bud_error_t bud_config_init(bud_config_t* config);
static bud_error_t bud_config_load_frontend_ifaces(
    JSON_Object* obj,
    bud_config_frontend_interface_t* interface);
static bud_error_t bud_config_load_frontend(JSON_Object* obj,
                                            bud_config_frontend_t* frontend);
static void bud_config_set_defaults(bud_config_t* config);
static void bud_config_set_frontend_defaults(bud_config_frontend_t* frontend);
static void bud_config_set_backend_defaults(bud_config_backend_t* backend);
static void bud_print_help(int argc, char** argv);
static void bud_print_version();
static void bud_config_print_default();
static void bud_config_finalize(bud_config_t* config);
static void bud_config_read_pool_conf(JSON_Object* obj,
                                      const char* key,
                                      bud_config_http_pool_t* pool);
static bud_error_t bud_config_format_proxyline(bud_config_t* config);
static bud_error_t bud_config_load_backend(
    bud_config_t* config,
    JSON_Object* obj,
    bud_config_backend_t* backend,
    bud_hashmap_t* map,
    unsigned int* ext_count);


int kBudSSLConfigIndex = -1;
int kBudSSLClientIndex = -1;
int kBudSSLSNIIndex = -1;
static const int kBudDefaultKeepalive = 3600;
static const int kBudBackendMapSize = 1024;
static const int kBudFileCacheSize = 64;

static const char bud_long_flags[] = "vi:c:dp";
static struct option bud_long_options[] = {
  { "version", 0, NULL, 'v' },
  { "config", 1, NULL, 'c' },
  { "piped-config", 0, NULL, 'p' },
  { "inline-config", 1, NULL, 'i' },
#ifndef _WIN32
  { "daemonize", 0, NULL, 'd' },
#endif  /* !_WIN32 */
  { "worker", 0, NULL, 1000 },
  { "default-config", 0, NULL, 1001 },
  { NULL, 0, NULL, 0 }
};
const char* kPipedConfigPath = "!config";


bud_error_t bud_config_new(int argc, char** argv, bud_config_t** out) {
  bud_error_t err;
  bud_config_t* config;
  int i;
  int r;
  size_t path_len;
  int c;
  int index;
  int loaded;

  config = calloc(1, sizeof(*config));
  if (config == NULL)
    return bud_error_str(kBudErrNoMem, "bud_config_t");

  loaded = 0;
  do {
    index = 0;
    c = getopt_long(argc, argv, bud_long_flags, bud_long_options, &index);
    switch (c) {
      case 'v':
        bud_print_version();
        err = bud_error(kBudErrSkip);
        goto fatal;
#ifndef _WIN32
      case 'd':
        config->is_daemon = 1;
#endif  /* !_WIN32 */
        break;
      case 'p':
      case 'i':
      case 'c':
        if (loaded) {
          err = bud_error(kBudErrMultipleConfigs);
          goto fatal;
        }
        loaded = 1;

        if (c == 'p') {
          config->piped = 1;
          config->path = kPipedConfigPath;
        } else {
          config->piped = 0;
          config->path = optarg;
          config->inlined = c == 'i';
        }
        break;
      case 1000:
        config->is_worker = 1;
        break;
      case 1001:
        bud_config_print_default();
        err = bud_error(kBudErrSkip);
        goto fatal;
      default:
        if (loaded)
          break;

        bud_print_help(argc, argv);
        goto no_config;
    }
  } while (c != -1);

  if (!config->piped) {
    config->piped_index = -1;
  } else {
    /* get_opt does not provide the argc offset so must manually retrieve it */
    for (i = 0; i < argc; i++) {
      if (strcmp(argv[i], "--piped-config") == 0 ||
          strcmp(argv[i], "-p") == 0) {
        config->piped_index = i;
        break;
      }
    }
  }

  /* CLI options */
  config->argc = argc;
  config->argv = argv;

  /* Get executable path */
  path_len = sizeof(config->exepath);
  r = uv_exepath(config->exepath, &path_len);
  ASSERT(path_len < sizeof(config->exepath), "Exepath OOB");

  if (r != 0) {
    bud_config_free(config);
    config = NULL;
    return bud_error_num(kBudErrExePath, r);
  }

  err = bud_hashmap_init(&config->files.hashmap, kBudFileCacheSize);
  if (!bud_is_ok(err))
    goto fatal;

  *out = config;
  return bud_ok();

no_config:
  free(config);
  return bud_error(kBudErrNoConfig);

fatal:
  free(config);
  return err;
}


bud_error_t bud_config_load(bud_config_t* config) {
  int i;
  bud_error_t err;
  JSON_Value* json;
  JSON_Value* val;
  JSON_Object* frontend;
  JSON_Object* obj;
  JSON_Object* log;
  JSON_Object* avail;
  JSON_Array* contexts;

  if (config->piped) {
    char* content;

    ASSERT(config->loop != NULL, "Loop should be present");
    err = bud_read_file_by_fd(config->loop, 0, &content);
    if (!bud_is_ok(err))
      goto end;

    err = bud_hashmap_insert(&config->files.hashmap,
                             kPipedConfigPath,
                             strlen(kPipedConfigPath),
                             content);
    if (!bud_is_ok(err)) {
      free(content);
      goto end;
    }

    json = json_parse_string(content);
  } else if (config->inlined) {
    json = json_parse_string(config->path);
  } else {
    const char* contents;

    err = bud_config_load_file(config, config->path, &contents);
    if (!bud_is_ok(err))
      goto end;
    json = json_parse_string(contents);
  }

  if (json == NULL) {
    err = bud_error_dstr(kBudErrJSONParse, config->path);
    goto end;
  }

  obj = json_value_get_object(json);
  if (obj == NULL) {
    err = bud_error(kBudErrJSONNonObjectRoot);
    goto failed_alloc_path;
  }

  err = bud_config_load_tracing(&config->trace,
                                json_object_get_object(obj, "tracing"));
  if (!bud_is_ok(err))
    goto failed_alloc_path;

  /* Allocate contexts and backends */
  contexts = json_object_get_array(obj, "contexts");
  config->context_count = contexts == NULL ? 0 : json_array_get_count(contexts);
  config->contexts = calloc(config->context_count + 1,
                            sizeof(*config->contexts));
  if (config->contexts == NULL) {
    err = bud_error_str(kBudErrNoMem, "bud_context_t");
    goto failed_alloc_contexts;
  }

  config->json = json;

  /* Workers configuration */
  config->worker_count = -1;
  config->restart_timeout = -1;
  config->master_ipc = -1;
  val = json_object_get_value(obj, "workers");
  if (val != NULL)
    config->worker_count = json_value_get_number(val);
  val = json_object_get_value(obj, "restart_timeout");
  if (val != NULL)
    config->restart_timeout = json_value_get_number(val);
  val = json_object_get_value(obj, "master_ipc");
  if (val != NULL)
    config->master_ipc = json_value_get_boolean(val);

  /* Logger configuration */
  log = json_object_get_object(obj, "log");
  config->log.stdio = -1;
  config->log.syslog = -1;
  if (log != NULL) {
    config->log.level = json_object_get_string(log, "level");
    config->log.facility = json_object_get_string(log, "facility");

    val = json_object_get_value(log, "stdio");
    if (val != NULL)
      config->log.stdio = json_value_get_boolean(val);
    val = json_object_get_value(log, "syslog");
    if (val != NULL)
      config->log.syslog = json_value_get_boolean(val);
  }

  /* Availability configuration */
  avail = json_object_get_object(obj, "availability");
  config->availability.death_timeout = -1;
  config->availability.revive_interval = -1;
  config->availability.retry_interval = -1;
  config->availability.max_retries = -1;
  if (avail != NULL) {
    val = json_object_get_value(avail, "death_timeout");
    if (val != NULL)
      config->availability.death_timeout = json_value_get_number(val);
    val = json_object_get_value(avail, "revive_interval");
    if (val != NULL)
      config->availability.revive_interval = json_value_get_number(val);
    val = json_object_get_value(avail, "retry_interval");
    if (val != NULL)
      config->availability.retry_interval = json_value_get_number(val);
    val = json_object_get_value(avail, "max_retries");
    if (val != NULL)
      config->availability.max_retries = json_value_get_number(val);
  }

  /* Frontend configuration */
  frontend = json_object_get_object(obj, "frontend");
  err = bud_config_load_frontend(frontend, &config->frontend);
  if (!bud_is_ok(err))
    goto failed_alloc_contexts;

  /* Load frontend's context */
  err = bud_context_load(frontend, &config->contexts[0]);
  if (!bud_is_ok(err))
    goto failed_alloc_contexts;

  /* Backend configuration */
  config->balance = json_object_get_string(obj, "balance");
  err = bud_config_load_backend_list(config,
                                      obj,
                                      &config->contexts[0].backend);
  if (!bud_is_ok(err))
    goto failed_alloc_contexts;

  /* User and group configuration */
  config->user = json_object_get_string(obj, "user");
  config->group = json_object_get_string(obj, "group");

  /* SNI configuration */
  bud_config_read_pool_conf(obj, "sni", &config->sni);

  /* OCSP Stapling configuration */
  bud_config_read_pool_conf(obj, "stapling", &config->stapling);

  /* SSL Contexts */

  /* TODO(indutny): sort them and do binary search */
  for (i = 0; i < config->context_count; i++) {
    bud_context_t* ctx;

    /* NOTE: contexts[0] - is a default context */
    ctx = &config->contexts[i + 1];
    obj = json_array_get_object(contexts, i);
    if (obj == NULL) {
      err = bud_error(kBudErrJSONNonObjectCtx);
      goto failed_load_context;
    }

    err = bud_context_load(obj, ctx);
    if (!bud_is_ok(err))
      goto failed_load_context;

    err = bud_config_load_backend_list(config, obj, &ctx->backend);
    if (!bud_is_ok(err))
      goto failed_load_context;
  }

  bud_config_set_defaults(config);

  return bud_config_init(config);

failed_load_context:
  /* Deinitalize contexts */
  for (i++; i >= 0; i--) {
    bud_context_t* ctx;

    ctx = &config->contexts[i];
    free(ctx->backend.list);
    ctx->backend.list = NULL;
  }

failed_alloc_contexts:
  free(config->contexts);
  config->contexts = NULL;
  free(config->trace.dso);
  config->trace.dso = NULL;

failed_alloc_path:
  json_value_free(json);
  config->json = NULL;

end:
  return err;
}


bud_error_t bud_config_load_frontend_ifaces(
    JSON_Object* obj,
    bud_config_frontend_interface_t* interface) {
  JSON_Array* arr;
  int i;

  arr = json_object_get_array(obj, "interfaces");
  interface->count = arr == NULL ? 0 : json_array_get_count(arr);
  if (interface->count == 0)
    return bud_ok();

  interface->list = calloc(interface->count, sizeof(*interface->list));
  if (interface->list == NULL)
    return bud_error_str(kBudErrNoMem, "bud_frontend_interface_t");

  for (i = 0; i < interface->count; i++)
    bud_config_load_addr(json_array_get_object(arr, i), &interface->list[i]);

  return bud_ok();
}


bud_error_t bud_config_load_frontend(JSON_Object* obj,
                                     bud_config_frontend_t* frontend) {
  JSON_Value* val;

  bud_config_load_addr(obj, (bud_config_addr_t*) frontend);

  frontend->max_send_fragment = -1;
  frontend->allow_half_open = -1;
  frontend->reneg_limit = -1;
  if (obj == NULL)
    return bud_ok();

  frontend->security = json_object_get_string(obj, "security");
  frontend->reneg_window = json_object_get_number(obj, "reneg_window");
  val = json_object_get_value(obj, "reneg_limit");
  if (val != NULL)
    frontend->reneg_limit = json_value_get_number(val);

  val = json_object_get_value(obj, "max_send_fragment");
  if (val != NULL)
    frontend->max_send_fragment = json_value_get_number(val);
  val = json_object_get_value(obj, "allow_half_open");
  if (val != NULL)
    frontend->allow_half_open = json_value_get_boolean(val);

  return bud_config_load_frontend_ifaces(obj, &frontend->interface);
}


bud_error_t bud_config_load_backend_list(bud_config_t* config,
                                         JSON_Object* obj,
                                         bud_config_backend_list_t* backends) {
  bud_error_t err;
  JSON_Array* backend;
  int i;

  backends->external_count = 0;
  err = bud_hashmap_init(&backends->external_map, kBudBackendMapSize);
  if (!bud_is_ok(err))
    return err;

  backend = json_object_get_array(obj, "backend");
  backends->count = backend == NULL ? 0 : json_array_get_count(backend);
  backends->list = calloc(backends->count, sizeof(*backends->list));
  if (backends->list == NULL)
    return bud_error_str(kBudErrNoMem, "bud_backend_list_t");

  for (i = 0; i < backends->count; i++) {
    err = bud_config_load_backend(config,
                                  json_array_get_object(backend, i),
                                  &backends->list[i],
                                  &backends->external_map,
                                  &backends->external_count);
    if (!bud_is_ok(err))
      break;
  }
  if (!bud_is_ok(err)) {
    free(backends->list);
    backends->list = NULL;
  }
  return err;
}


bud_error_t bud_config_load_backend(bud_config_t* config,
                                    JSON_Object* obj,
                                    bud_config_backend_t* backend,
                                    bud_hashmap_t* map,
                                    unsigned int* ext_count) {
  bud_error_t err;
  JSON_Value* val;
  const char* external;
  int r;

  bud_config_load_addr(obj, (bud_config_addr_t*) backend);
  backend->config = config;
  backend->xforward = -1;

  val = json_object_get_value(obj, "proxyline");
  if (json_value_get_type(val) == JSONString) {
    const char* pline;

    pline = json_value_get_string(val);
    if (strcmp(pline, "haproxy") == 0)
      backend->proxyline = kBudProxylineHAProxy;
    else if (strcmp(pline, "json") == 0)
      backend->proxyline = kBudProxylineJSON;
    else
      return bud_error_dstr(kBudErrProxyline, pline);
  } else {
    backend->proxyline = val != NULL && json_value_get_boolean(val) ?
        kBudProxylineHAProxy :
        kBudProxylineNone;
  }

  val = json_object_get_value(obj, "x-forward");
  if (val != NULL)
    backend->xforward = json_value_get_boolean(val);

  /* Set defaults here to use them in sni.c */
  bud_config_set_backend_defaults(backend);

  r = bud_config_str_to_addr(backend->host, backend->port, &backend->addr);
  if (r != 0)
    return bud_error_num(kBudErrPton, r);

  external = json_object_get_string(obj, "external");
  if (external == NULL)
    return bud_ok();

  /* Insert backend into a hashmap */
  err = bud_hashmap_insert(map, external, strlen(external), backend);
  if (!bud_is_ok(err))
    return err;

  (*ext_count)++;

  return bud_ok();
}


void bud_config_read_pool_conf(JSON_Object* obj,
                               const char* key,
                               bud_config_http_pool_t* pool) {
  JSON_Object* p;

  p = json_object_get_object(obj, key);
  if (p != NULL) {
    pool->enabled = json_object_get_boolean(p, "enabled");
    if (pool->enabled == -1)
      pool->enabled = 0;
    pool->port = (uint16_t) json_object_get_number(p, "port");
    pool->host = json_object_get_string(p, "host");
    pool->url = json_object_get_string(p, "url");
  }
}


void bud_config_finalize(bud_config_t* config) {
  if (config->sni.pool != NULL)
    bud_http_pool_free(config->sni.pool);
  config->sni.pool = NULL;
  if (config->stapling.pool != NULL)
    bud_http_pool_free(config->stapling.pool);
  config->stapling.pool = NULL;
}


bud_error_t bud_config_free_files(bud_hashmap_item_t* item, void* arg) {
  free(item->value);
  return bud_ok();
}


void bud_config_free(bud_config_t* config) {
  int i;

  /* Free all reload-dependent resources */
  bud_config_finalize(config);
  if (config->loop != NULL)
    uv_run(config->loop, UV_RUN_NOWAIT);

  for (i = 0; i < config->context_count + 1; i++)
    bud_context_free(&config->contexts[i]);
  free(config->contexts);
  config->contexts = NULL;

  bud_logger_free(config->logger);
  config->logger = NULL;

  bud_hashmap_iterate(&config->files.hashmap, bud_config_free_files, NULL);
  bud_hashmap_destroy(&config->files.hashmap);

  json_value_free(config->json);
  config->json = NULL;

  free(config->files.str);
  config->files.str = NULL;

  bud_config_trace_free(&config->trace);

  /* Free rest */
  free(config->workers);
  config->workers = NULL;

  free(config);
}


void bud_print_help(int argc, char** argv) {
  ASSERT(argc >= 1, "Not enough arguments");
  fprintf(stdout, "Usage: %s [options]\n\n", argv[0]);
  fprintf(stdout, "options:\n");
  fprintf(stdout, "  --version, -v              Print bud version\n");
  fprintf(stdout, "  --config PATH, -c PATH     Load JSON configuration\n");
  fprintf(stdout, "  --default-config           Print default JSON config\n");
  fprintf(stdout, "  --piped-config             Pipe JSON configuration ie cat <config> | ./bud ...\n");
#ifndef _WIN32
  fprintf(stdout, "  --daemon, -d               Daemonize process\n");
#endif  /* !_WIN32 */
  fprintf(stdout, "\n");
}


void bud_print_version() {
  fprintf(stdout,
          "v%d.%d.%d\n",
          BUD_VERSION_MAJOR,
          BUD_VERSION_MINOR,
          BUD_VERSION_PATCH);
}


void bud_config_print_default() {
  bud_config_t config;
  bud_config_backend_t backend;
  bud_context_t context;

  memset(&backend, 0, sizeof(backend));
  memset(&config, 0, sizeof(config));
  memset(&context, 0, sizeof(context));

  /* Set zero-y values */
  config.worker_count = -1;
  config.restart_timeout = -1;
  config.master_ipc = -1;
  config.log.stdio = -1;
  config.log.syslog = -1;
  config.frontend.keepalive = -1;
  config.frontend.max_send_fragment = -1;
  config.frontend.allow_half_open = -1;
  config.availability.death_timeout = -1;
  config.availability.revive_interval = -1;
  config.availability.retry_interval = -1;
  config.availability.max_retries = -1;
  config.context_count = 0;
  config.contexts = &context;
  context.backend.list = &backend;
  context.backend.list[0].keepalive = -1;
  context.backend.count = 1;
  context.ticket_timeout = -1;
  context.ticket_rotate = -1;

  bud_config_set_defaults(&config);

  fprintf(stdout, "{\n");
  fprintf(stdout, "  \"daemon\": false,\n");
  fprintf(stdout, "  \"workers\": %d,\n", config.worker_count);
  fprintf(stdout, "  \"restart_timeout\": %d,\n", config.restart_timeout);
  fprintf(stdout, "  \"master_ipc\": false,\n");
  fprintf(stdout, "  \"log\": {\n");
  fprintf(stdout, "    \"level\": \"%s\",\n", config.log.level);
  fprintf(stdout, "    \"facility\": \"%s\",\n", config.log.facility);
  fprintf(stdout,
          "    \"stdio\": %s,\n",
          config.log.stdio ? "true" : "false");
  fprintf(stdout,
          "    \"syslog\": %s\n",
          config.log.syslog ? "true" : "false");
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"availability\": {\n");
  fprintf(stdout,
      "    \"death_timeout\": %d,\n",
          config.availability.death_timeout);
  fprintf(stdout,
          "    \"revive_interval\": %d,\n",
          config.availability.revive_interval);
  fprintf(stdout,
          "    \"retry_interval\": %d,\n",
          config.availability.retry_interval);
  fprintf(stdout,
          "    \"max_retries\": %d\n",
          config.availability.max_retries);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"frontend\": {\n");
  fprintf(stdout, "    \"port\": %d,\n", config.frontend.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.frontend.host);
  fprintf(stdout, "    \"keepalive\": %d,\n", config.frontend.keepalive);
  fprintf(stdout, "    \"security\": \"%s\",\n", config.frontend.security);
  fprintf(stdout, "    \"server_preference\": true,\n");
  fprintf(stdout,
          "    \"max_send_fragment\": %d,\n",
          config.frontend.max_send_fragment);
  if (config.frontend.allow_half_open)
    fprintf(stdout, "    \"allow_half_open\": true,\n");
  else
    fprintf(stdout, "    \"allow_half_open\": false,\n");
#ifdef OPENSSL_NPN_NEGOTIATED
  /* Sorry, hard-coded */
  fprintf(stdout, "    \"npn\": [\"http/1.1\", \"http/1.0\"],\n");
#endif  /* OPENSSL_NPN_NEGOTIATED */
  if (context.ciphers != NULL)
    fprintf(stdout, "    \"ciphers\": \"%s\",\n", context.ciphers);
  else
    fprintf(stdout, "    \"ciphers\": null,\n");
  if (context.ecdh != NULL)
    fprintf(stdout, "    \"ecdh\": \"%s\",\n", context.ecdh);
  else
    fprintf(stdout, "    \"ecdh\": null,\n");
  if (context.dh_file != NULL)
    fprintf(stdout, "    \"dh\": \"%s\",\n", context.dh_file);
  else
    fprintf(stdout, "    \"dh\": null,\n");
  fprintf(stdout, "    \"cert\": \"%s\",\n", context.cert_file);
  fprintf(stdout, "    \"key\": \"%s\",\n", context.key_file);
  fprintf(stdout, "    \"passphrase\": null,\n");
  fprintf(stdout, "    \"ticket_key\": null,\n");
  fprintf(stdout, "    \"ticket_timeout\": %d,\n", context.ticket_timeout);
  fprintf(stdout, "    \"ticket_rotate\": %d,\n", context.ticket_rotate);
  fprintf(stdout, "    \"request_cert\": false,\n");
  fprintf(stdout, "    \"optional_cert\": false,\n");
  fprintf(stdout, "    \"ca\": null,\n");
  fprintf(stdout, "    \"reneg_window\": %d,\n", config.frontend.reneg_window);
  fprintf(stdout, "    \"reneg_limit\": %d\n", config.frontend.reneg_limit);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"balance\": \"%s\",\n", config.balance);
  fprintf(stdout, "  \"user\": null,\n");
  fprintf(stdout, "  \"group\": null,\n");
  fprintf(stdout, "  \"backend\": [{\n");
  fprintf(stdout, "    \"port\": %d,\n", context.backend.list[0].port);
  fprintf(stdout, "    \"host\": \"%s\",\n", context.backend.list[0].host);
  fprintf(stdout,
          "    \"keepalive\": %d,\n",
          context.backend.list[0].keepalive);
  fprintf(stdout, "    \"proxyline\": false,\n");
  fprintf(stdout, "    \"x-forward\": false\n");
  fprintf(stdout, "  }],\n");
  fprintf(stdout, "  \"sni\": {\n");
  fprintf(stdout, "    \"enabled\": false,\n");
  fprintf(stdout, "    \"port\": %d,\n", config.sni.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.sni.host);
  fprintf(stdout, "    \"url\": \"%s\"\n", config.sni.url);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"stapling\": {\n");
  fprintf(stdout, "    \"enabled\": false,\n");
  fprintf(stdout, "    \"port\": %d,\n", config.stapling.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.stapling.host);
  fprintf(stdout, "    \"url\": \"%s\"\n", config.stapling.url);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"contexts\": [],\n");
  fprintf(stdout, "  \"tracing\": {\n");
  fprintf(stdout, "    \"dso\": []\n");
  fprintf(stdout, "  }\n");
  fprintf(stdout, "}\n");
}


#define DEFAULT(param, null, value)                                           \
    do {                                                                      \
      if ((param) == (null))                                                  \
        (param) = (value);                                                    \
    } while (0)

void bud_config_set_defaults(bud_config_t* config) {
  int i;

  DEFAULT(config->worker_count, -1, 1);
  DEFAULT(config->restart_timeout, -1, 250);
  DEFAULT(config->master_ipc, -1, 0);
  DEFAULT(config->log.level, NULL, "info");
  DEFAULT(config->log.facility, NULL, "user");
  DEFAULT(config->log.stdio, -1, 1);
  DEFAULT(config->log.syslog, -1, 0);
  DEFAULT(config->availability.death_timeout, -1, 1000);
  DEFAULT(config->availability.revive_interval, -1, 2500);
  DEFAULT(config->availability.retry_interval, -1, 250);
  DEFAULT(config->availability.max_retries, -1, 5);
  DEFAULT(config->balance, NULL, "roundrobin");

  bud_config_set_frontend_defaults(&config->frontend);

  for (i = 0; i < config->context_count + 1; i++) {
    bud_context_t* ctx;
    int j;

    ctx = &config->contexts[i];
    if (ctx->cert_files == NULL)
      DEFAULT(ctx->cert_file, NULL, "keys/cert.pem");
    if (ctx->key_files == NULL)
      DEFAULT(ctx->key_file, NULL, "keys/key.pem");
    DEFAULT(ctx->ciphers,
            NULL,
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-GCM-SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA256:"
            "DHE-RSA-AES256-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-SHA256:"
            "ECDHE-RSA-AES256-SHA256:"
            "DHE-RSA-AES256-SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES128-SHA256:"
            "ECDHE-RSA-AES128-SHA256:"
            "DHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES128-SHA256:"
            "ECDHE-ECDSA-AES256-SHA:"
            "ECDHE-RSA-AES256-SHA:"
            "ECDHE-ECDSA-AES128-SHA:"
            "ECDHE-RSA-AES128-SHA:"
            "DHE-RSA-AES128-SHA:"
            "AES256-GCM-SHA384:"
            "AES128-GCM-SHA256:"
            "AES256-SHA256:"
            "AES128-SHA256:"
            "AES128-SHA:"
            "DES-CBC3-SHA");
    DEFAULT(ctx->ticket_timeout, -1, 3600);
    DEFAULT(ctx->ticket_rotate, -1, 3600);
    for (j = 0; j < ctx->backend.count; j++)
      bud_config_set_backend_defaults(&ctx->backend.list[j]);
  }

  DEFAULT(config->sni.port, 0, 9000);
  DEFAULT(config->sni.host, NULL, "127.0.0.1");
  DEFAULT(config->sni.url, NULL, "/bud/sni/%s");
  DEFAULT(config->stapling.port, 0, 9000);
  DEFAULT(config->stapling.host, NULL, "127.0.0.1");
  DEFAULT(config->stapling.url, NULL, "/bud/stapling/%s");
}


void bud_config_set_frontend_defaults(bud_config_frontend_t* frontend) {
  int i;

  DEFAULT(frontend->port, 0, 1443);
  DEFAULT(frontend->host, NULL, "0.0.0.0");
  DEFAULT(frontend->security, NULL, "ssl23");
  DEFAULT(frontend->keepalive, -1, kBudDefaultKeepalive);
  DEFAULT(frontend->max_send_fragment, -1, 1400);
  DEFAULT(frontend->allow_half_open, -1, 0);
  DEFAULT(frontend->reneg_window, 0, 600);
  DEFAULT(frontend->reneg_limit, -1, 3);

  for (i = 0; i < frontend->interface.count; i++) {
    DEFAULT(frontend->interface.list[i].port, 0, 1443);
    DEFAULT(frontend->interface.list[i].host, NULL, "0.0.0.0");
  }
}


void bud_config_set_backend_defaults(bud_config_backend_t* backend) {
  DEFAULT(backend->port, 0, 8000);
  DEFAULT(backend->host, NULL, "127.0.0.1");
  DEFAULT(backend->keepalive, -1, kBudDefaultKeepalive);
  DEFAULT(backend->xforward, -1, 0);
}

#undef DEFAULT


bud_error_t bud_config_init(bud_config_t* config) {
  bud_error_t err;
  int i;
  int r;

  /* Get addresses of frontend and backend */
  r = bud_config_str_to_addr(config->frontend.host,
                             config->frontend.port,
                             &config->frontend.addr);
  if (r != 0)
    return bud_error_num(kBudErrPton, r);

  for (i = 0; i < config->frontend.interface.count; i++) {
    bud_config_addr_t* addr;

    addr = &config->frontend.interface.list[i];
    r = bud_config_str_to_addr(addr->host, addr->port, &addr->addr);
    if (r != 0)
      return bud_error_num(kBudErrPton, r);
  }

  err = bud_config_format_proxyline(config);
  if (!bud_is_ok(err))
    return err;

  i = 0;

  config->balance_e = bud_config_balance_to_enum(config->balance);

  /* At least one backend should be present for non-SNI balancing */
  if (config->contexts[0].backend.count == 0 &&
      config->balance_e != kBudBalanceSNI) {
    err = bud_error(kBudErrNoBackend);
    goto fatal;
  }

  /* Get indexes for SSL_set_ex_data()/SSL_get_ex_data() */
  if (kBudSSLClientIndex == -1) {
    kBudSSLConfigIndex = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    kBudSSLClientIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    kBudSSLSNIIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    kBudSSLTicketKeyIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (kBudSSLConfigIndex == -1 ||
        kBudSSLClientIndex == -1 ||
        kBudSSLSNIIndex == -1 ||
        kBudSSLTicketKeyIndex == -1) {
      err = bud_error(kBudErrNoSSLIndex);
      goto fatal;
    }
  }

#ifndef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  if (config->context_count != 0) {
    err = bud_error(kBudErrSNINotSupported);
    goto fatal;
  }
#endif  /* !SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */

  /* Allocate workers */
  if (!config->is_worker && config->worker_count != 0) {
    config->workers = calloc(config->worker_count, sizeof(*config->workers));
    if (config->workers == NULL) {
      err = bud_error_str(kBudErrNoMem, "workers");
      goto fatal;
    }
  }

  /* Initialize logger */
  config->logger = bud_logger_new(config, &err);
  if (!bud_is_ok(err))
    goto fatal;

  err = bud_config_init_tracing(&config->trace);
  if (!bud_is_ok(err))
    goto fatal;

  if (config->is_worker || config->worker_count == 0) {
    /* Connect to SNI server */
    if (config->sni.enabled) {
      config->sni.pool = bud_http_pool_new(config,
                                           config->sni.host,
                                           config->sni.port,
                                           &err);
      if (config->sni.pool == NULL)
        goto fatal;
    }

    /* Connect to OCSP Stapling server */
    if (config->stapling.enabled) {
      config->stapling.pool = bud_http_pool_new(config,
                                                config->stapling.host,
                                                config->stapling.port,
                                                &err);
      if (config->stapling.pool == NULL)
        goto fatal;
    }
  }

  /* Init all contexts */
  for (i = 0; i < config->context_count + 1; i++) {
    err = bud_context_init(config, &config->contexts[i]);
    if (!bud_is_ok(err))
      goto fatal;
  }

  return bud_ok();

fatal:
  /* Free all allocated contexts */
  do
    bud_context_free(&config->contexts[i--]);
  while (i >= 0);

  return err;
}


bud_context_t* bud_config_select_context(bud_config_t* config,
                                         const char* servername,
                                         size_t servername_len) {
  int i;

  /* TODO(indutny): Binary search */
  for (i = 0; i < config->context_count; i++) {
    bud_context_t* ctx;

    ctx = &config->contexts[i + 1];

    if (servername_len != ctx->servername_len)
      continue;

    if (strncasecmp(servername, ctx->servername, ctx->servername_len) != 0)
      continue;

    return ctx;
  }

  return &config->contexts[0];
}


bud_error_t bud_config_format_proxyline(bud_config_t* config) {
  int r;
  char host[INET6_ADDRSTRLEN];
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;

  addr4 = (struct sockaddr_in*) &config->frontend.addr;
  addr6 = (struct sockaddr_in6*) &config->frontend.addr;

  if (config->frontend.addr.ss_family == AF_INET)
    r = uv_inet_ntop(AF_INET, &addr4->sin_addr, host, sizeof(host));
  else
    r = uv_inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
  if (r != 0)
    return bud_error(kBudErrNtop);

  r = snprintf(config->proxyline_fmt.haproxy,
               sizeof(config->proxyline_fmt.haproxy),
               "PROXY %%s %%s %s %%hu %hu\r\n",
               host,
               config->frontend.port);
  ASSERT(r < (int) sizeof(config->proxyline_fmt.haproxy),
         "Proxyline format overflowed");

  r = snprintf(config->proxyline_fmt.json,
               sizeof(config->proxyline_fmt.json),
               "BUD {\"family\":\"%%s\","
                   "\"bud\":{\"host\":\"%s\",\"port\":%hu},"
                   "\"peer\":{"
                     "\"host\":\"%%s\","
                     "\"port\":%%hu,"
                     "\"cn\":%%c%%s%%c}"
                   "}\r\n",
               host,
               config->frontend.port);
  ASSERT(r < (int) sizeof(config->proxyline_fmt.json),
         "Proxyline format overflowed");

  return bud_ok();
}
