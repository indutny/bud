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

#include "config.h"
#include "common.h"
#include "ocsp.h"
#include "http-pool.h"
#include "logger.h"
#include "master.h"  /* bud_worker_t */
#include "version.h"

static bud_error_t bud_config_init(bud_config_t* config);
static void bud_config_load_addr(JSON_Object* obj,
                                 bud_config_addr_t* addr);
static bud_error_t bud_config_load_ca_arr(X509_STORE** store,
                                          const JSON_Array* ca);
static bud_error_t bud_config_load_ca_file(X509_STORE** store,
                                           const char* filename);
static bud_error_t bud_config_load_frontend(JSON_Object* obj,
                                            bud_config_frontend_t* frontend);
static void bud_config_copy(bud_config_t* dst, bud_config_t* src);
static void bud_config_destroy(bud_config_t* config);
static void bud_config_set_defaults(bud_config_t* config);
static void bud_config_set_backend_defaults(bud_config_backend_t* backend);
static void bud_print_help(int argc, char** argv);
static void bud_print_version();
static void bud_config_print_default();
static void bud_config_finalize(bud_config_t* config);
static void bud_config_read_pool_conf(JSON_Object* obj,
                                      const char* key,
                                      bud_config_http_pool_t* pool);
#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
static int bud_config_select_sni_context(SSL* s, int* ad, void* arg);
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */
#ifdef OPENSSL_NPN_NEGOTIATED
static char* bud_config_encode_npn(bud_config_t* config,
                                   const JSON_Array* npn,
                                   size_t* len,
                                   bud_error_t* err);
static int bud_config_advertise_next_proto(SSL* s,
                                           const unsigned char** data,
                                           unsigned int* len,
                                           void* arg);
#endif  /* OPENSSL_NPN_NEGOTIATED */
static bud_error_t bud_config_verify_all_strings(const JSON_Array* npn,
                                                 const char* name);
static bud_error_t bud_config_format_proxyline(bud_config_t* config);
static int bud_config_verify_cert(int status, X509_STORE_CTX* s);


int kBudSSLConfigIndex = -1;
int kBudSSLClientIndex = -1;
int kBudSSLSNIIndex = -1;
static const int kBudDefaultKeepalive = 3600;


bud_config_t* bud_config_cli_load(int argc, char** argv, bud_error_t* err) {
  int c;
  int index;
  int is_daemon;
  int is_worker;
  size_t path_len;
  bud_config_t* config;

  struct option long_options[] = {
    { "version", 0, NULL, 'v' },
    { "config", 1, NULL, 'c' },
    { "inline-config", 1, NULL, 'i' },
#ifndef _WIN32
    { "daemonize", 0, NULL, 'd' },
#endif  /* !_WIN32 */
    { "worker", 0, NULL, 1000 },
    { "default-config", 0, NULL, 1001 },
    { NULL, 0, NULL, 0 }
  };

  *err = bud_ok();
  config = NULL;
  is_daemon = 0;
  is_worker = 0;
  do {
    index = 0;
    c = getopt_long(argc, argv, "vi:c:d", long_options, &index);
    switch (c) {
      case 'v':
        bud_print_version();
        c = -1;
        break;
      case 'i':
      case 'c':
        config = bud_config_load(optarg, c == 'i', err);
        if (config == NULL) {
          ASSERT(!bud_is_ok(*err), "Config load failed without error");
          c = -1;
          break;
        }
        if (is_daemon)
          config->is_daemon = 1;
        if (is_worker)
          config->is_worker = 1;
        break;
#ifndef _WIN32
      case 'd':
        is_daemon = 1;
        if (config != NULL)
          config->is_daemon = 1;
#endif  /* !_WIN32 */
        break;
      case 1000:
        is_worker = 1;
        if (config != NULL)
          config->is_worker = 1;
        break;
      case 1001:
        bud_config_print_default();
        c = -1;
        break;
      default:
        if (config == NULL)
          bud_print_help(argc, argv);
        c = -1;
        break;
    }
  } while (c != -1);

  if (config != NULL) {
    int r;

    /* CLI options */
    config->argc = argc;
    config->argv = argv;

    /* Get executable path */
    path_len = sizeof(config->exepath);
    r = uv_exepath(config->exepath, &path_len);
    ASSERT(path_len < sizeof(config->exepath), "Exepath OOB");

    config->exepath[path_len] = 0;
    if (r != 0) {
      bud_config_free(config);
      config = NULL;
      *err = bud_error_num(kBudErrExePath, r);
    }

    /* Initialize config */
    *err = bud_config_init(config);
    if (!bud_is_ok(*err)) {
      bud_config_free(config);
      return NULL;
    }
  }

  return config;
}


void bud_config_copy(bud_config_t* dst, bud_config_t* src) {
  /* Load params from the new one */
  dst->loop = src->loop;
  dst->json = src->json;
  dst->logger = src->logger;
  dst->path = src->path;
  dst->inlined = src->inlined;
  dst->contexts = src->contexts;
  dst->restart_timeout = src->restart_timeout;
  dst->balance = src->balance;
  dst->backend = src->backend;
  src->backend = NULL;
  memcpy(&dst->log, &src->log, sizeof(src->log));
  memcpy(&dst->availability, &src->availability, sizeof(src->availability));
  memcpy(&dst->frontend, &src->frontend, sizeof(src->frontend));
  memcpy(&dst->sni, &src->sni, sizeof(src->sni));
  memcpy(&dst->stapling, &src->stapling, sizeof(src->stapling));
}


bud_error_t bud_config_reload(bud_config_t* config) {
  bud_error_t err;
  bud_config_t* loaded;
  bud_config_t restore;

  loaded = bud_config_load(config->path, config->inlined, &err);
  if (!bud_is_ok(err))
    return err;

  memset(&restore, 0, sizeof(restore));
  bud_config_copy(&restore, config);
  bud_config_copy(config, loaded);

  /* Initialize config with new params */
  err = bud_config_init(config);

  /* Restore everything on failure */
  if (!bud_is_ok(err)) {
    bud_config_copy(config, &restore);
    bud_config_free(loaded);
    return err;
  }

  free(loaded);
  bud_config_destroy(&restore);
  return bud_ok();
}


bud_error_t bud_config_verify_all_strings(const JSON_Array* arr,
                                          const char* name) {
  int i;
  int count;

  if (arr == NULL)
    return bud_ok();

  count = json_array_get_count(arr);
  for (i = 0; i < count; i++) {
    if (json_value_get_type(json_array_get_value(arr, i)) == JSONString)
      continue;
    return bud_error_str(kBudErrNonString, name);
  }

  return bud_ok();
}


bud_config_t* bud_config_load(const char* path, int inlined, bud_error_t* err) {
  int i;
  JSON_Value* json;
  JSON_Value* val;
  JSON_Object* obj;
  JSON_Object* tmp;
  JSON_Object* log;
  JSON_Object* avail;
  JSON_Array* contexts;
  JSON_Array* backend;
  bud_config_t* config;
  bud_context_t* ctx;

  if (inlined)
    json = json_parse_string(path);
  else
    json = json_parse_file(path);

  if (json == NULL) {
    *err = bud_error_str(kBudErrJSONParse, path);
    goto end;
  }

  obj = json_value_get_object(json);
  if (obj == NULL) {
    *err = bud_error(kBudErrJSONNonObjectRoot);
    goto failed_get_object;
  }

  config = calloc(1, sizeof(*config));
  if (config == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_config_t");
    goto failed_get_object;
  }

  /* Copy path or inlined config value */
  config->path = strdup(path);
  if (config->path == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_config_t strcpy(path)");
    goto failed_alloc_path;
  }

  config->inlined = inlined;

  /* Allocate contexts and backends */
  contexts = json_object_get_array(obj, "contexts");
  backend = json_object_get_array(obj, "backend");
  config->context_count = contexts == NULL ? 0 : json_array_get_count(contexts);
  config->backend_count = backend == NULL ? 0 : json_array_get_count(backend);
  config->contexts = calloc(config->context_count + 1,
                            sizeof(*config->contexts));
  config->backend = calloc(config->backend_count, sizeof(*config->backend));

  if (config->contexts == NULL || config->backend == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_context_t");
    goto failed_get_index;
  }

  config->json = json;

  /* Workers configuration */
  config->worker_count = -1;
  config->restart_timeout = -1;
  val = json_object_get_value(obj, "workers");
  if (val != NULL)
    config->worker_count = json_value_get_number(val);
  val = json_object_get_value(obj, "restart_timeout");
  if (val != NULL)
    config->restart_timeout = json_value_get_number(val);

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
  *err = bud_config_load_frontend(json_object_get_object(obj, "frontend"),
                                  &config->frontend);
  if (!bud_is_ok(*err))
    goto failed_get_index;

  /* Backend configuration */
  config->balance = json_object_get_string(obj, "balance");
  for (i = 0; i < config->backend_count; i++) {
    bud_config_load_backend(config,
                            json_array_get_object(backend, i),
                            &config->backend[i]);
  }

  /* SNI configuration */
  bud_config_read_pool_conf(obj, "sni", &config->sni);

  /* OCSP Stapling configuration */
  bud_config_read_pool_conf(obj, "stapling", &config->stapling);

  /* SSL Contexts */

  /* TODO(indutny): sort them and do binary search */
  for (i = 0; i < config->context_count; i++) {
    /* NOTE: contexts[0] - is a default context */
    ctx = &config->contexts[i + 1];
    obj = json_array_get_object(contexts, i);
    if (obj == NULL) {
      *err = bud_error(kBudErrJSONNonObjectCtx);
      goto failed_get_index;
    }

    ctx->servername = json_object_get_string(obj, "servername");
    ctx->servername_len = ctx->servername == NULL ? 0 : strlen(ctx->servername);
    ctx->cert_file = json_object_get_string(obj, "cert");
    ctx->key_file = json_object_get_string(obj, "key");
    ctx->npn = json_object_get_array(obj, "npn");
    ctx->ciphers = json_object_get_string(obj, "ciphers");
    ctx->ecdh = json_object_get_string(obj, "ecdh");
    ctx->ticket_key = json_object_get_string(obj, "ticket_key");
    val = json_object_get_value(obj, "ca");
    if (json_value_get_type(val) == JSONString)
      ctx->ca_file = json_value_get_string(val);
    else
      ctx->ca_array = json_value_get_array(val);
    val = json_object_get_value(obj, "request_cert");
    if (val != NULL)
      ctx->request_cert = json_value_get_boolean(val);

    tmp = json_object_get_object(obj, "backend");
    if (tmp != NULL) {
      ctx->backend = &ctx->backend_st;
      bud_config_load_backend(config, tmp, ctx->backend);
    }

    *err = bud_config_verify_all_strings(ctx->npn, "npn");
    if (!bud_is_ok(*err))
      goto failed_get_index;
  }

  bud_config_set_defaults(config);

  *err = bud_ok();
  return config;

failed_get_index:
  free(config->contexts);
  config->contexts = NULL;
  free(config->backend);
  config->backend = NULL;
  free(config->path);
  config->path = NULL;

failed_alloc_path:
  free(config);

failed_get_object:
  json_value_free(json);

end:
  return NULL;
}


void bud_config_load_addr(JSON_Object* obj, bud_config_addr_t* addr) {
  JSON_Value* val;

  /* Backend configuration */
  addr->keepalive = -1;
  if (obj == NULL)
    return;

  addr->port = (uint16_t) json_object_get_number(obj, "port");
  addr->host = json_object_get_string(obj, "host");
  val = json_object_get_value(obj, "keepalive");
  if (val != NULL)
    addr->keepalive = json_value_get_number(val);
}

bud_error_t bud_config_load_ca_file(X509_STORE** store, const char* filename) {
  BIO* b;
  X509* x509;
  bud_error_t err;

  b = BIO_new_file(filename, "r");
  if (b == NULL)
    return bud_error_str(kBudErrLoadCert, filename);

  x509 = NULL;
  *store = X509_STORE_new();
  if (*store == NULL) {
    err = bud_error_str(kBudErrNoMem, "CA store");
    goto fatal;
  }

  while ((x509 = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
    if (x509 == NULL) {
      err = bud_error_str(kBudErrParseCert, filename);
      goto fatal;
    }

    if (X509_STORE_add_cert(*store, x509) != 1) {
      err = bud_error(kBudErrAddCert);
      goto fatal;
    }
    X509_free(x509);
    x509 = NULL;
  }

  err = bud_ok();

fatal:
  if (x509 != NULL)
    X509_free(x509);
  BIO_free_all(b);
  return bud_ok();
}


bud_error_t bud_config_load_frontend(JSON_Object* obj,
                                     bud_config_frontend_t* frontend) {
  bud_error_t err;
  JSON_Value* val;

  bud_config_load_addr(obj, (bud_config_addr_t*) frontend);

  frontend->server_preference = -1;
  frontend->ssl3 = -1;
  frontend->max_send_fragment = -1;
  frontend->allow_half_open = -1;
  frontend->request_cert = -1;
  frontend->ca_store = NULL;
  if (obj == NULL)
    return bud_ok();

  frontend->security = json_object_get_string(obj, "security");
  frontend->ciphers = json_object_get_string(obj, "ciphers");
  frontend->ecdh = json_object_get_string(obj, "ecdh");
  frontend->cert_file = json_object_get_string(obj, "cert");
  frontend->key_file = json_object_get_string(obj, "key");
  frontend->reneg_window = json_object_get_number(obj, "reneg_window");
  frontend->reneg_limit = json_object_get_number(obj, "reneg_limit");
  frontend->ticket_key = json_object_get_string(obj, "ticket_key");
  val = json_object_get_value(obj, "ca");
  if (json_value_get_type(val) == JSONString)
    frontend->ca_file = json_value_get_string(val);
  else
    frontend->ca_array = json_value_get_array(val);

  /* Get and verify NPN */
  frontend->npn = json_object_get_array(obj, "npn");
  err = bud_config_verify_all_strings(frontend->npn, "npn");
  if (!bud_is_ok(err))
    goto fatal;

  val = json_object_get_value(obj, "server_preference");
  if (val != NULL)
    frontend->server_preference = json_value_get_boolean(val);
  val = json_object_get_value(obj, "ssl3");
  if (val != NULL)
    frontend->ssl3 = json_value_get_boolean(val);
  val = json_object_get_value(obj, "max_send_fragment");
  if (val != NULL)
    frontend->max_send_fragment = json_value_get_number(val);
  val = json_object_get_value(obj, "allow_half_open");
  if (val != NULL)
    frontend->allow_half_open = json_value_get_boolean(val);
  val = json_object_get_value(obj, "request_cert");
  if (val != NULL)
    frontend->request_cert = json_value_get_boolean(val);

  if (frontend->ca_array != NULL)
    err = bud_config_load_ca_arr(&frontend->ca_store, frontend->ca_array);
  else if (frontend->ca_file != NULL)
    err = bud_config_load_ca_file(&frontend->ca_store, frontend->ca_file);

fatal:
  return err;
}


bud_error_t bud_config_load_backend(bud_config_t* config,
                                    JSON_Object* obj,
                                    bud_config_backend_t* backend) {
  JSON_Value* val;

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
      return bud_error_str(kBudErrProxyline, pline);
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

  return bud_ok();
}


void bud_config_read_pool_conf(JSON_Object* obj,
                               const char* key,
                               bud_config_http_pool_t* pool) {
  JSON_Object* p;

  p = json_object_get_object(obj, key);
  if (p != NULL) {
    pool->enabled = json_object_get_boolean(p, "enabled");
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


void bud_config_destroy(bud_config_t* config) {
  int i;

  bud_config_finalize(config);
  if (config->loop != NULL)
    uv_run(config->loop, UV_RUN_NOWAIT);

  for (i = 0; i < config->context_count + 1; i++)
    bud_context_free(&config->contexts[i]);
  free(config->contexts);
  config->contexts = NULL;

  bud_logger_free(config->logger);
  config->logger = NULL;

  json_value_free(config->json);
  config->json = NULL;

  free(config->path);
  config->path = NULL;

  if (config->frontend.ca_store != NULL)
    X509_STORE_free(config->frontend.ca_store);
  config->frontend.ca_store = NULL;

  for (i = 0; i < config->backend_count; i++) {
    if (config->backend[i].revive_timer != NULL) {
      uv_close((uv_handle_t*) config->backend[i].revive_timer,
               (uv_close_cb) free);
      config->backend[i].revive_timer = NULL;
    }
  }
  free(config->backend);
  config->backend = NULL;
}


void bud_config_free(bud_config_t* config) {
  /* Free all reload-dependent resources */
  bud_config_destroy(config);

  /* Free rest */
  free(config->workers);
  config->workers = NULL;

  free(config);
}


void bud_context_free(bud_context_t* context) {
  if (context == NULL)
    return;

  SSL_CTX_free(context->ctx);
  if (context->cert != NULL)
    X509_free(context->cert);
  if (context->issuer != NULL)
    X509_free(context->issuer);
  if (context->ca_store != NULL)
    X509_STORE_free(context->ca_store);
  if (context->ocsp_id != NULL)
    OCSP_CERTID_free(context->ocsp_id);
  if (context->ocsp_der_id != NULL)
    free(context->ocsp_der_id);
  free(context->npn_line);
  context->ctx = NULL;
  context->cert = NULL;
  context->issuer = NULL;
  context->ca_store = NULL;
  context->npn_line = NULL;
  context->ocsp_id = NULL;
  context->ocsp_der_id = NULL;
}


void bud_print_help(int argc, char** argv) {
  ASSERT(argc >= 1, "Not enough arguments");
  fprintf(stdout, "Usage: %s [options]\n\n", argv[0]);
  fprintf(stdout, "options:\n");
  fprintf(stdout, "  --version, -v              Print bud version\n");
  fprintf(stdout, "  --config PATH, -c PATH     Load JSON configuration\n");
  fprintf(stdout, "  --default-config           Print default JSON config\n");
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

  memset(&backend, 0, sizeof(backend));
  memset(&config, 0, sizeof(config));

  /* Set zero-y values */
  config.worker_count = -1;
  config.log.stdio = -1;
  config.log.syslog = -1;
  config.frontend.keepalive = -1;
  config.frontend.ssl3 = -1;
  config.frontend.max_send_fragment = -1;
  config.frontend.allow_half_open = -1;
  config.frontend.request_cert = -1;
  config.backend_count = 1;
  config.backend = &backend;
  config.backend[0].keepalive = -1;
  config.restart_timeout = -1;
  config.availability.death_timeout = -1;
  config.availability.revive_interval = -1;
  config.availability.retry_interval = -1;
  config.availability.max_retries = -1;

  bud_config_set_defaults(&config);

  fprintf(stdout, "{\n");
  fprintf(stdout, "  \"daemon\": false,\n");
  fprintf(stdout, "  \"workers\": %d,\n", config.worker_count);
  fprintf(stdout, "  \"restart_timeout\": %d,\n", config.restart_timeout);
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
  if (config.frontend.ssl3)
    fprintf(stdout, "    \"ssl3\": true,\n");
  else
    fprintf(stdout, "    \"ssl3\": false,\n");
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
  if (config.frontend.ciphers != NULL)
    fprintf(stdout, "    \"ciphers\": \"%s\",\n", config.frontend.ciphers);
  else
    fprintf(stdout, "    \"ciphers\": null,\n");
  if (config.frontend.ecdh != NULL)
    fprintf(stdout, "    \"ecdh\": \"%s\",\n", config.frontend.ecdh);
  else
    fprintf(stdout, "    \"ecdh\": null,\n");
  fprintf(stdout, "    \"cert\": \"%s\",\n", config.frontend.cert_file);
  fprintf(stdout, "    \"key\": \"%s\",\n", config.frontend.key_file);
  fprintf(stdout, "    \"ticket_key\": null,\n");
  fprintf(stdout, "    \"request_cert\": false,\n");
  fprintf(stdout, "    \"ca\": null,\n");
  fprintf(stdout, "    \"reneg_window\": %d,\n", config.frontend.reneg_window);
  fprintf(stdout, "    \"reneg_limit\": %d\n", config.frontend.reneg_limit);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"balance\": \"%s\",\n", config.balance);
  fprintf(stdout, "  \"backend\": [{\n");
  fprintf(stdout, "    \"port\": %d,\n", config.backend[0].port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.backend[0].host);
  fprintf(stdout, "    \"keepalive\": %d,\n", config.backend[0].keepalive);
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
  fprintf(stdout, "  \"contexts\": []\n");
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
  DEFAULT(config->log.level, NULL, "info");
  DEFAULT(config->log.facility, NULL, "user");
  DEFAULT(config->log.stdio, -1, 1);
  DEFAULT(config->log.syslog, -1, 0);
  DEFAULT(config->availability.death_timeout, -1, 1000);
  DEFAULT(config->availability.revive_interval, -1, 2500);
  DEFAULT(config->availability.retry_interval, -1, 250);
  DEFAULT(config->availability.max_retries, -1, 5);
  DEFAULT(config->frontend.port, 0, 1443);
  DEFAULT(config->frontend.host, NULL, "0.0.0.0");
  DEFAULT(config->frontend.security, NULL, "ssl23");
  DEFAULT(config->frontend.ecdh, NULL, "prime256v1");
  DEFAULT(config->frontend.keepalive, -1, kBudDefaultKeepalive);
  DEFAULT(config->frontend.server_preference, -1, 1);
  DEFAULT(config->frontend.ssl3, -1, 0);
  DEFAULT(config->frontend.max_send_fragment, -1, 1400);
  DEFAULT(config->frontend.allow_half_open, -1, 0);
  DEFAULT(config->frontend.request_cert, -1, 0);
  DEFAULT(config->frontend.cert_file, NULL, "keys/cert.pem");
  DEFAULT(config->frontend.key_file, NULL, "keys/key.pem");
  DEFAULT(config->frontend.reneg_window, 0, 600);
  DEFAULT(config->frontend.reneg_limit, 0, 3);
  DEFAULT(config->balance, NULL, "roundrobin");

  for (i = 0; i < config->backend_count; i++)
    bud_config_set_backend_defaults(&config->backend[i]);

  DEFAULT(config->sni.port, 0, 9000);
  DEFAULT(config->sni.host, NULL, "127.0.0.1");
  DEFAULT(config->sni.url, NULL, "/bud/sni/%s");
  DEFAULT(config->stapling.port, 0, 9000);
  DEFAULT(config->stapling.host, NULL, "127.0.0.1");
  DEFAULT(config->stapling.url, NULL, "/bud/stapling/%s");
}


void bud_config_set_backend_defaults(bud_config_backend_t* backend) {
  DEFAULT(backend->port, 0, 8000);
  DEFAULT(backend->host, NULL, "127.0.0.1");
  DEFAULT(backend->keepalive, -1, kBudDefaultKeepalive);
  DEFAULT(backend->xforward, -1, 0);
}

#undef DEFAULT


#ifdef OPENSSL_NPN_NEGOTIATED
char* bud_config_encode_npn(bud_config_t* config,
                            const JSON_Array* npn,
                            size_t* len,
                            bud_error_t* err) {
  int i;
  char* npn_line;
  size_t npn_line_len;
  unsigned int offset;
  int npn_count;
  const char* npn_item;
  int npn_item_len;

  /* Try global defaults */
  if (npn == NULL)
    npn = config->frontend.npn;
  if (npn == NULL) {
    *err = bud_ok();
    *len = 0;
    return NULL;
  }

  /* Calculate storage requirements */
  npn_count = json_array_get_count(npn);
  npn_line_len = 0;
  for (i = 0; i < npn_count; i++)
    npn_line_len += 1 + strlen(json_array_get_string(npn, i));

  if (npn_line_len != 0) {
    npn_line = malloc(npn_line_len);
    if (npn_line == NULL) {
      *err = bud_error_str(kBudErrNoMem, "NPN copy");
      return NULL;
    }
  }

  /* Fill npn line */
  for (i = 0, offset = 0; i < npn_count; i++) {
    npn_item = json_array_get_string(npn, i);
    npn_item_len = strlen(npn_item);

    npn_line[offset++] = npn_item_len;
    memcpy(npn_line + offset, npn_item, npn_item_len);
    offset += npn_item_len;
  }
  ASSERT(offset == npn_line_len, "NPN Line overflow");

  *len = npn_line_len;
  *err = bud_ok();

  return npn_line;
}
#endif  /* OPENSSL_NPN_NEGOTIATED */


bud_error_t bud_config_load_ca_arr(X509_STORE** store,
                                   const JSON_Array* ca) {
  int i;
  int count;
  bud_error_t err;

  err = bud_config_verify_all_strings(ca, "ca");
  if (!bud_is_ok(err))
    return err;

  *store = X509_STORE_new();
  if (*store == NULL)
    return bud_error_str(kBudErrNoMem, "CA store");

  count = json_array_get_count(ca);
  for (i = 0; i < count; i++) {
    const char* cert;
    BIO* b;
    X509* x509;

    cert = json_array_get_string(ca, i);
    b = BIO_new_mem_buf((void*) cert, -1);
    if (b == NULL)
      return bud_error_str(kBudErrNoMem, "CA store bio");

    while ((x509 = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
      if (x509 == NULL) {
        err = bud_error_str(kBudErrParseCert, cert);
        break;
      }

      if (X509_STORE_add_cert(*store, x509) != 1) {
        err = bud_error(kBudErrAddCert);
        break;
      }
      X509_free(x509);
      x509 = NULL;
    }
    BIO_free_all(b);
    if (x509 != NULL)
      X509_free(x509);
  }

  return err;
}


bud_error_t bud_config_new_ssl_ctx(bud_config_t* config,
                                   bud_context_t* context) {
  SSL_CTX* ctx;
  int ecdh_nid;
  EC_KEY* ecdh;
  bud_error_t err;
  int options;
  int r;
  const char* ticket_key;
  size_t max_len;

  if (context->backend != NULL) {
    if (context->backend->keepalive == -1)
      context->backend->keepalive = kBudDefaultKeepalive;
    r = bud_config_str_to_addr(context->backend->host,
                               context->backend->port,
                               &context->backend->addr);
    if (r != 0)
      return bud_error_num(kBudErrPton, r);
  }

  /* Decode ticket_key */
  ticket_key = context->ticket_key == NULL ? config->frontend.ticket_key :
                                             context->ticket_key;
  if (ticket_key != NULL) {
    max_len = sizeof(context->ticket_key_storage);
    if (bud_base64_decode(context->ticket_key_storage,
                          max_len,
                          ticket_key,
                          strlen(ticket_key)) < max_len) {
      return bud_error(kBudErrSmallTicketKey);
    }
  }

  /* Choose method, tlsv1_2 by default */
  if (config->frontend.method == NULL) {
    if (strcmp(config->frontend.security, "tls1.1") == 0)
      config->frontend.method = TLSv1_1_server_method();
    else if (strcmp(config->frontend.security, "tls1.0") == 0)
      config->frontend.method = TLSv1_server_method();
    else if (strcmp(config->frontend.security, "tls1.2") == 0)
      config->frontend.method = TLSv1_2_server_method();
    else if (strcmp(config->frontend.security, "ssl3") == 0)
      config->frontend.method = SSLv3_server_method();
    else
      config->frontend.method = SSLv23_server_method();
  }

  ctx = SSL_CTX_new(config->frontend.method);
  if (ctx == NULL)
    return bud_error_str(kBudErrNoMem, "SSL_CTX");

  ecdh = NULL;
  if (!SSL_CTX_set_ex_data(ctx, kBudSSLConfigIndex, config)) {
    err = bud_error_str(kBudErrNoMem, "SSL_CTX");
    goto fatal;
  }

  /* Disable sessions, they won't work with cluster anyway */
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

  if (config->frontend.max_send_fragment)
    SSL_CTX_set_max_send_fragment(ctx, config->frontend.max_send_fragment);

  if (ticket_key != NULL) {
    SSL_CTX_set_tlsext_ticket_keys(ctx,
                                   context->ticket_key_storage,
                                   sizeof(context->ticket_key_storage));
  }

  /* Load CA chain */
  if (context->ca_array != NULL)
    err = bud_config_load_ca_arr(&context->ca_store, context->ca_array);
  else if (context->ca_file != NULL)
    err = bud_config_load_ca_file(&context->ca_store, context->ca_file);
  else
    err = bud_ok();
  if (!bud_is_ok(err))
    goto fatal;

  /* Because of how OpenSSL is managing X509_STORE associated with ctx,
   * there is no way to swap them without reallocating them again.
   * Perform client cert validation manually.
   */
  if (config->frontend.request_cert || context->request_cert) {
    SSL_CTX_set_verify(ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       bud_config_verify_cert);
  } else {
    /* Just verify anything */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, bud_config_verify_cert);
  }

  /* ECDH curve selection */
  if (context->ecdh != NULL || config->frontend.ecdh != NULL) {
    if (context->ecdh != NULL)
      ecdh_nid = OBJ_sn2nid(context->ecdh);
    else
      ecdh_nid = OBJ_sn2nid(config->frontend.ecdh);

    if (ecdh_nid == NID_undef) {
      ecdh = NULL;
      err = bud_error_str(kBudErrECDHNotFound,
                          context->ecdh == NULL ? config->frontend.ecdh :
                                                  context->ecdh);
      goto fatal;
    }

    ecdh = EC_KEY_new_by_curve_name(ecdh_nid);
    if (ecdh == NULL) {
      err = bud_error_str(kBudErrNoMem, "EC_KEY");
      goto fatal;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
  }
  ecdh = NULL;

  /* Cipher suites */
  if (context->ciphers != NULL)
    SSL_CTX_set_cipher_list(ctx, context->ciphers);
  else if (config->frontend.ciphers != NULL)
    SSL_CTX_set_cipher_list(ctx, config->frontend.ciphers);

  /* Disable SSL2 */
  options = SSL_OP_NO_SSLv2 | SSL_OP_ALL;
  if (!config->frontend.ssl3)
    options |= SSL_OP_NO_SSLv3;

  if (config->frontend.server_preference)
    options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
  SSL_CTX_set_options(ctx, options);

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  SSL_CTX_set_tlsext_servername_callback(ctx,
                                         bud_config_select_sni_context);
  SSL_CTX_set_tlsext_servername_arg(ctx, config);
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */

#ifdef OPENSSL_NPN_NEGOTIATED
  context->npn_line = bud_config_encode_npn(config,
                                            context->npn,
                                            &context->npn_line_len,
                                            &err);
  if (!bud_is_ok(err))
    goto fatal;

  if (context->npn_line != NULL) {
    SSL_CTX_set_next_protos_advertised_cb(ctx,
                                          bud_config_advertise_next_proto,
                                          context);
  }
#else  /* !OPENSSL_NPN_NEGOTIATED */
  err = bud_error(kBudErrNPNNotSupported);
  goto fatal;
#endif  /* OPENSSL_NPN_NEGOTIATED */

  SSL_CTX_set_tlsext_status_cb(ctx, bud_client_stapling_cb);

  context->ctx = ctx;
  return bud_ok();

fatal:
  if (ecdh != NULL)
    EC_KEY_free(ecdh);

  SSL_CTX_free(ctx);
  return err;
}


const char* bud_context_get_ocsp_id(bud_context_t* context,
                                    size_t* size) {
  char* encoded;
  unsigned char* pencoded;
  size_t encoded_len;
  char* base64;
  size_t base64_len;

  if (context->ocsp_id == NULL)
    return NULL;

  base64 = NULL;
  encoded = NULL;
  /* Return cached id */
  if (context->ocsp_der_id != NULL)
    goto done;

  encoded_len = i2d_OCSP_CERTID(context->ocsp_id, NULL);
  base64_len = bud_base64_encoded_size(encoded_len);
  encoded = malloc(encoded_len);
  base64 = malloc(base64_len);
  if (encoded == NULL || base64 == NULL)
    goto done;

  pencoded = (unsigned char*) encoded;
  i2d_OCSP_CERTID(context->ocsp_id, &pencoded);

  bud_base64_encode(encoded, encoded_len, base64, base64_len);
  context->ocsp_der_id = base64;
  context->ocsp_der_id_len = base64_len;
  base64 = NULL;

done:
  free(encoded);
  free(base64);
  *size = context->ocsp_der_id_len;
  return context->ocsp_der_id;
}


const char* bud_context_get_ocsp_req(bud_context_t* context,
                                     size_t* size,
                                     char** ocsp_request,
                                     size_t* ocsp_request_len) {
  STACK_OF(OPENSSL_STRING)* urls;
  OCSP_REQUEST* req;
  OCSP_CERTID* id;
  char* encoded;
  unsigned char* pencoded;
  size_t encoded_len;

  urls = NULL;
  id = NULL;
  encoded = NULL;

  /* Cached url */
  if (context->ocsp_url != NULL)
    goto has_url;

  urls = X509_get1_ocsp(context->cert);
  if (urls == NULL)
    goto done;

  context->ocsp_url = sk_OPENSSL_STRING_pop(urls);
  context->ocsp_url_len = strlen(context->ocsp_url);

has_url:
  if (context->ocsp_url == NULL)
    goto done;

  id = OCSP_CERTID_dup(context->ocsp_id);
  if (id == NULL)
    goto done;

  /* Create request */
  req = OCSP_REQUEST_new();
  if (req == NULL)
    goto done;
  if (!OCSP_request_add0_id(req, id))
    goto done;
  id = NULL;

  encoded_len = i2d_OCSP_REQUEST(req, NULL);
  encoded = malloc(encoded_len);
  if (encoded == NULL)
    goto done;

  pencoded = (unsigned char*) encoded;
  i2d_OCSP_REQUEST(req, &pencoded);
  OCSP_REQUEST_free(req);

  *ocsp_request = encoded;
  *ocsp_request_len = encoded_len;
  encoded = NULL;

done:
  if (id != NULL)
    OCSP_CERTID_free(id);
  if (urls != NULL)
    X509_email_free(urls);
  if (encoded != NULL)
    free(encoded);

  *size = context->ocsp_url_len;
  return context->ocsp_url;
}


bud_error_t bud_config_init(bud_config_t* config) {
  int i;
  int r;
  bud_context_t* ctx;
  bud_error_t err;
  const char* cert_file;
  const char* key_file;
  BIO* cert_bio;

  /* Get addresses of frontend and backend */
  r = bud_config_str_to_addr(config->frontend.host,
                             config->frontend.port,
                             &config->frontend.addr);
  if (r != 0)
    return bud_error_num(kBudErrPton, r);

  for (i = 0; i < config->backend_count; i++) {
    r = bud_config_str_to_addr(config->backend[i].host,
                               config->backend[i].port,
                               &config->backend[i].addr);
    if (r != 0)
      return bud_error_num(kBudErrPton, r);
  }

  err = bud_config_format_proxyline(config);
  if (!bud_is_ok(err))
    return err;

  /* Balance str to enum */
  if (strcmp(config->balance, "sni") == 0)
    config->balance_e = kBudBalanceSNI;
  else
    config->balance_e = kBudBalanceRoundRobin;

  i = 0;

  if (config->backend_count == 0 && config->balance_e == kBudBalanceRoundRobin)
    return bud_error(kBudErrNoBackend);

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

  /* Load all contexts */
  for (i = 0; i < config->context_count + 1; i++) {
    ctx = &config->contexts[i];

    err = bud_config_new_ssl_ctx(config, ctx);
    if (!bud_is_ok(err))
      goto fatal;

    /* Default context */
    if (i == 0) {
      cert_file = config->frontend.cert_file;
      key_file = config->frontend.key_file;
    } else {
      cert_file = ctx->cert_file;
      key_file = ctx->key_file;
    }

    cert_bio = BIO_new_file(cert_file, "r");
    if (cert_bio == NULL) {
      err = bud_error_str(kBudErrLoadCert, cert_file);
      goto fatal;
    }

    r = bud_context_use_certificate_chain(ctx, cert_bio);
    BIO_free_all(cert_bio);
    if (!r) {
      err = bud_error_str(kBudErrParseCert, cert_file);
      goto fatal;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx->ctx,
                                     key_file,
                                     SSL_FILETYPE_PEM)) {
      err = bud_error_str(kBudErrParseKey, key_file);
      goto fatal;
    }
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


#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
int bud_config_select_sni_context(SSL* s, int* ad, void* arg) {
  bud_config_t* config;
  bud_context_t* ctx;
  const char* servername;

  config = arg;
  servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

  /* No servername - no context selection */
  if (servername == NULL)
    return SSL_TLSEXT_ERR_OK;

  /* Async SNI */
  ctx = SSL_get_ex_data(s, kBudSSLSNIIndex);

  /* Normal SNI */
  if (ctx == NULL)
    ctx = bud_config_select_context(config, servername, strlen(servername));

  if (ctx != NULL) {
    SSL_set_SSL_CTX(s, ctx->ctx);
    s->verify_mode = ctx->ctx->verify_mode;
    if (!SSL_set_ex_data(s, kBudSSLSNIIndex, ctx))
      return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  return SSL_TLSEXT_ERR_OK;
}
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */


#ifdef OPENSSL_NPN_NEGOTIATED
int bud_config_advertise_next_proto(SSL* s,
                                    const unsigned char** data,
                                    unsigned int* len,
                                    void* arg) {
  bud_context_t* context;

  context = arg;

  *data = (const unsigned char*) context->npn_line;
  *len = context->npn_line_len;

  return SSL_TLSEXT_ERR_OK;
}
#endif  /* OPENSSL_NPN_NEGOTIATED */


int bud_config_str_to_addr(const char* host,
                           uint16_t port,
                           struct sockaddr_storage* addr) {
  int r;
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;

  addr4 = (struct sockaddr_in*) addr;
  addr6 = (struct sockaddr_in6*) addr;

  r = uv_inet_pton(AF_INET, host, &addr4->sin_addr);
  if (r == 0) {
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
  } else {
    addr6->sin6_family = AF_INET6;
    r = uv_inet_pton(AF_INET6, host, &addr6->sin6_addr);
    if (r == 0)
      addr6->sin6_port = htons(port);
  }

  return r;
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
int bud_context_use_certificate_chain(bud_context_t* ctx, BIO *in) {
  int ret;
  X509* x;
  X509* ca;
  int r;
  unsigned long err;

  ERR_clear_error();

  ret = 0;
  x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);

  if (x == NULL) {
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx->ctx, x);
  ctx->cert = x;
  ctx->issuer = NULL;

  if (ERR_peek_error() != 0) {
    /* Key/certificate mismatch doesn't imply ret==0 ... */
    ret = 0;
  }

  if (ret) {
    /**
     * If we could set up our certificate, now proceed to
     * the CA certificates.
     */
    if (ctx->ctx->extra_certs != NULL) {
      sk_X509_pop_free(ctx->ctx->extra_certs, X509_free);
      ctx->ctx->extra_certs = NULL;
    }

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
      r = SSL_CTX_add_extra_chain_cert(ctx->ctx, ca);

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

      /* Find issuer */
      if (ctx->issuer != NULL || X509_check_issued(ca, x) != X509_V_OK)
        continue;
      ctx->issuer = ca;
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
  if (ret) {
    /* Try getting issuer from cert store */
    if (ctx->issuer == NULL) {
      X509_STORE* store;
      X509_STORE_CTX store_ctx;

      store = SSL_CTX_get_cert_store(ctx->ctx);
      ret = X509_STORE_CTX_init(&store_ctx, store, NULL, NULL);
      if (!ret)
        goto fatal;

      ret = X509_STORE_CTX_get1_issuer(&ctx->issuer, &store_ctx, ctx->cert);
      X509_STORE_CTX_cleanup(&store_ctx);

      ret = ret < 0 ? 0 : 1;
      /* NOTE: get_cert_store doesn't increment reference count */
    } else {
      /* Increment issuer reference count */
      CRYPTO_add(&ctx->issuer->references, 1, CRYPTO_LOCK_X509);
    }

    if (ctx->issuer != NULL) {
      /* Get ocsp_id */
      ctx->ocsp_id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
      if (ctx->ocsp_id == NULL)
        goto fatal;
    }
  }

fatal:
  if (!ret && ctx->issuer != NULL) {
    X509_free(ctx->issuer);
    ctx->issuer = NULL;
  }

  if (ctx->cert != x && x != NULL)
    X509_free(x);

  return ret;
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


int bud_config_verify_cert(int status, X509_STORE_CTX* s) {
  bud_config_t* config;
  bud_context_t* ctx;
  X509_STORE_CTX store_ctx;
  X509* cert;
  X509_STORE* store;
  SSL* ssl;
  int r;

  ssl = X509_STORE_CTX_get_ex_data(s, SSL_get_ex_data_X509_STORE_CTX_idx());
  ASSERT(ssl != NULL, "STORE_CTX without associated ssl");

  cert = s->cert;
  ctx = SSL_get_ex_data(ssl, kBudSSLSNIIndex);
  config = SSL_CTX_get_ex_data(ssl->ctx, kBudSSLConfigIndex);
  ASSERT(config != NULL, "Config not present in SSL");

  if (ctx != NULL && ctx->ca_store != NULL)
    store = ctx->ca_store;
  else if (config->frontend.ca_store != NULL)
    store = config->frontend.ca_store;
  else
    store = NULL;

  /* No certificate store, validate cert if present */
  if (store == NULL) {
    if (cert != NULL)
      return SSL_get_verify_result(ssl) == X509_V_OK ? 1 : 0;
    else
      return config->frontend.request_cert ? 1 : 0;
  }

  if (!X509_STORE_CTX_init(&store_ctx, store, cert, NULL))
    return 0;

  r = X509_verify_cert(&store_ctx);
  X509_STORE_CTX_cleanup(&store_ctx);

  return r;
}
