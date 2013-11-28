#include <getopt.h>  /* getopt */
#include <stdio.h>  /* fprintf */
#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset, strlen, strncmp */
#include <strings.h>  /* strcasecmp */

#include "uv.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "config.h"
#include "common.h"
#include "version.h"
#include "logger.h"
#include "master.h"  /* bud_worker_t */
#include "redis.h"

static bud_error_t bud_config_init(bud_config_t* config);
static void bud_config_set_defaults(bud_config_t* config);
static void bud_print_help(int argc, char** argv);
static void bud_print_version();
static void bud_config_print_default();
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
static int bud_config_str_to_addr(const char* host,
                                  uint16_t port,
                                  struct sockaddr_storage* addr);
static bud_error_t bud_config_verify_npn(const JSON_Array* npn);


bud_config_t* bud_config_cli_load(uv_loop_t* loop,
                                  int argc,
                                  char** argv,
                                  bud_error_t* err) {
  int c;
  int r;
  int index;
  int is_daemon;
  int is_worker;
  size_t path_len;
  bud_config_t* config;

  struct option long_options[] = {
    { "version", 0, NULL, 'v' },
    { "config", 1, NULL, 'c' },
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
    c = getopt_long(argc, argv, "vc:d", long_options, &index);
    switch (c) {
      case 'v':
        bud_print_version();
        break;
      case 'c':
        config = bud_config_load(loop,optarg, err);
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


bud_error_t bud_config_verify_npn(const JSON_Array* npn) {
  int i;
  int npn_count;

  if (npn == NULL)
    return bud_ok();

  npn_count = json_array_get_count(npn);
  for (i = 0; i < npn_count; i++) {
    if (json_value_get_type(json_array_get_value(npn, i)) == JSONString)
      continue;
    return bud_error(kBudErrNPNNonString);
  }

  return bud_ok();
}


bud_config_t* bud_config_load(uv_loop_t* loop,
                              const char* path,
                              bud_error_t* err) {
  int i;
  int context_count;
  JSON_Value* json;
  JSON_Value* val;
  JSON_Object* obj;
  JSON_Object* log;
  JSON_Object* frontend;
  JSON_Object* backend;
  JSON_Object* redis;
  JSON_Array* contexts;
  bud_config_t* config;
  bud_context_t* ctx;

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
  contexts = json_object_get_array(obj, "contexts");
  context_count = contexts == NULL ? 0 : json_array_get_count(contexts);

  config = calloc(1,
                  sizeof(*config) +
                      (context_count - 1) * sizeof(*config->contexts));
  if (config == NULL) {
    *err = bud_error_str(kBudErrNoMem, "bud_config_t");
    goto failed_get_object;
  }

  config->loop = loop;
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

  /* Frontend configuration */

  frontend = json_object_get_object(obj, "frontend");
  config->frontend.proxyline = -1;
  config->frontend.keepalive = -1;
  config->frontend.server_preference = -1;
  if (frontend != NULL) {
    config->frontend.port = (uint16_t) json_object_get_number(frontend, "port");
    config->frontend.host = json_object_get_string(frontend, "host");
    config->frontend.security = json_object_get_string(frontend, "security");
    config->frontend.npn = json_object_get_array(frontend, "npn");
    config->frontend.ciphers = json_object_get_string(frontend, "ciphers");

    *err = bud_config_verify_npn(config->frontend.npn);
    if (!bud_is_ok(*err))
      goto failed_get_index;

    val = json_object_get_value(frontend, "proxyline");
    if (val != NULL)
      config->frontend.proxyline = json_value_get_boolean(val);
    val = json_object_get_value(frontend, "keepalive");
    if (val != NULL)
      config->frontend.keepalive = json_value_get_number(val);
    val = json_object_get_value(frontend, "server_preference");
    if (val != NULL)
      config->frontend.server_preference = json_value_get_boolean(val);
  }

  /* Backend configuration */
  backend = json_object_get_object(obj, "backend");
  config->backend.keepalive = -1;
  if (backend != NULL) {
    config->backend.port = (uint16_t) json_object_get_number(backend, "port");
    config->backend.host = json_object_get_string(backend, "host");
    val = json_object_get_value(backend, "keepalive");
    if (val != NULL)
      config->backend.keepalive = json_value_get_number(val);
  }

  /* Redis configuration */
  redis = json_object_get_object(obj, "redis");
  if (redis != NULL) {
    config->redis.enabled = json_object_get_boolean(redis, "enabled");
    config->redis.port = (uint16_t) json_object_get_number(redis, "port");
    config->redis.host = json_object_get_string(redis, "host");
    config->redis.query_fmt = json_object_get_string(redis, "query");

    config->redis.reconnect_timeout = -1;
    val = json_object_get_value(redis, "reconnect_timeout");
    if (val != NULL)
      config->redis.reconnect_timeout = json_value_get_number(val);
  }

  /* SSL Contexts */

  /* TODO(indutny): sort them and do binary search */
  for (i = 0; i < context_count; i++) {
    ctx = &config->contexts[i];
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

    *err = bud_config_verify_npn(ctx->npn);
    if (!bud_is_ok(*err))
      goto failed_get_index;
  }
  config->context_count = context_count;

  bud_config_set_defaults(config);

  *err = bud_ok();
  return config;

failed_get_index:
  free(config);

failed_get_object:
  json_value_free(json);

end:
  return NULL;
}


void bud_config_free(bud_config_t* config) {
  int i;

  for (i = 0; i < config->context_count; i++)
    bud_context_free(&config->contexts[i]);
  free(config->workers);
  config->workers = NULL;
  if (config->redis.ctx != NULL)
    bud_redis_free(config->redis.ctx);
  config->redis.ctx = NULL;
  if (config->logger != NULL)
    bud_logger_free(config);
  config->logger = NULL;

  json_value_free(config->json);
  config->json = NULL;
  free(config);
}


void bud_context_free(bud_context_t* context) {
  SSL_CTX_free(context->ctx);
  free(context->npn_line);
  context->npn_line = NULL;
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
  fprintf(stdout, "v%d.%d\n", BUD_VERSION_MAJOR, BUD_VERSION_MINOR);
}


void bud_config_print_default() {
  int i;
  bud_config_t config;
  bud_context_t* ctx;

  memset(&config, 0, sizeof(config));

  /* Set zero-y values */
  config.worker_count = -1;
  config.log.stdio = -1;
  config.log.syslog = -1;
  config.frontend.keepalive = -1;
  config.backend.keepalive = -1;
  config.redis.reconnect_timeout = -1;
  config.restart_timeout = -1;

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
  fprintf(stdout, "  \"frontend\": {\n");
  fprintf(stdout, "    \"port\": %d,\n", config.frontend.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.frontend.host);
  fprintf(stdout, "    \"keepalive\": %d,\n", config.frontend.keepalive);
  fprintf(stdout, "    \"proxyline\": false,\n");
  fprintf(stdout, "    \"security\": \"%s\",\n", config.frontend.security);
  fprintf(stdout, "    \"server_preference\": true,\n");
#ifdef OPENSSL_NPN_NEGOTIATED
  /* Sorry, hard-coded */
  fprintf(stdout, "    \"npn\": [\"http/1.1\", \"http/1.0\"],\n");
#endif  /* OPENSSL_NPN_NEGOTIATED */
  if (config.frontend.ciphers != NULL)
    fprintf(stdout, "    \"ciphers\": \"%s\"\n", config.frontend.ciphers);
  else
    fprintf(stdout, "    \"ciphers\": null\n");
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"backend\": {\n");
  fprintf(stdout, "    \"port\": %d,\n", config.backend.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.backend.host);
  fprintf(stdout, "    \"keepalive\": %d\n", config.backend.keepalive);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"redis\": {\n");
  fprintf(stdout, "    \"enabled\": false,\n");
  fprintf(stdout, "    \"port\": %d,\n", config.redis.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.redis.host);
  fprintf(stdout, "    \"query\": \"%s\",\n", config.redis.query_fmt);
  fprintf(stdout,
          "    \"reconnect_timeout\": %d\n",
          config.redis.reconnect_timeout);
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"contexts\": [");
  for (i = 0; i < config.context_count; i++) {
    ctx = &config.contexts[i];

    fprintf(stdout, i == 0 ? "{\n" : "  }, {\n");
    if (ctx->servername != NULL)
      fprintf(stdout, "    \"servername\": \"%s\",\n", ctx->servername);
    else
      fprintf(stdout, "    \"servername\": null,\n");
    fprintf(stdout, "    \"cert\": \"%s\",\n", ctx->cert_file);
    fprintf(stdout, "    \"key\": \"%s\",\n", ctx->key_file);
#ifdef OPENSSL_NPN_NEGOTIATED
    /* Sorry, hard-coded */
    fprintf(stdout, "    \"npn\": null,\n");
#endif  /* OPENSSL_NPN_NEGOTIATED */
    fprintf(stdout, "    \"ciphers\": null\n");

    if (i == config.context_count - 1)
      fprintf(stdout, "  }");
    else
      fprintf(stdout, "  },\n");
  }
  fprintf(stdout, "]\n");
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
  DEFAULT(config->frontend.port, 0, 1443);
  DEFAULT(config->frontend.host, NULL, "0.0.0.0");
  DEFAULT(config->frontend.proxyline, -1, 0);
  DEFAULT(config->frontend.security, NULL, "ssl23");
  DEFAULT(config->frontend.keepalive, -1, 3600);
  DEFAULT(config->frontend.server_preference, -1, 1);
  DEFAULT(config->backend.port, 0, 8000);
  DEFAULT(config->backend.host, NULL, "127.0.0.1");
  DEFAULT(config->backend.keepalive, -1, 3600);
  DEFAULT(config->context_count, 0, 1);

  if (config->context_count == 0)
    config->context_count = 1;

  DEFAULT(config->redis.reconnect_timeout, -1, 250);
  DEFAULT(config->redis.port, 0, 6379);
  DEFAULT(config->redis.host, NULL, "127.0.0.1");
  DEFAULT(config->redis.query_fmt, NULL, "HGET bud/sni %b");

  for (i = 0; i < config->context_count; i++) {
    DEFAULT(config->contexts[i].cert_file, NULL, "keys/cert.pem");
    DEFAULT(config->contexts[i].key_file, NULL, "keys/key.pem");
  }
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
  for (i = 0; i < npn_count; i++) {
    npn_line_len += 1 + strlen(json_array_get_string(npn, i));
  }

  npn_line = malloc(npn_line_len);
  if (npn_line == NULL) {
    *err = bud_error_str(kBudErrNoMem, "NPN copy");
    return NULL;
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


bud_error_t bud_config_new_ssl_ctx(bud_config_t* config,
                                   bud_context_t* context) {
  SSL_CTX* ctx;
  bud_error_t err;
  int options;

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
  SSL_CTX_set_session_cache_mode(ctx,
                                 SSL_SESS_CACHE_SERVER |
                                 SSL_SESS_CACHE_NO_INTERNAL |
                                 SSL_SESS_CACHE_NO_AUTO_CLEAR);
  if (context->ciphers != NULL)
    SSL_CTX_set_cipher_list(ctx, context->ciphers);
  else if (config->frontend.ciphers != NULL)
    SSL_CTX_set_cipher_list(ctx, config->frontend.ciphers);

  /* Disable SSL2 */
  options = SSL_OP_NO_SSLv2 | SSL_OP_ALL;

  if (config->frontend.server_preference)
    options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
  SSL_CTX_set_options(ctx, options);

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  if (config->context_count > 1) {
    SSL_CTX_set_tlsext_servername_callback(ctx,
                                           bud_config_select_sni_context);
    SSL_CTX_set_tlsext_servername_arg(ctx, config);
  }
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */

  if (context->npn != NULL) {
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
  }

  context->ctx = ctx;
  return bud_ok();

fatal:
  SSL_CTX_free(ctx);
  return err;
}


bud_error_t bud_config_init(bud_config_t* config) {
  int i;
  int r;
  bud_context_t* ctx;
  bud_error_t err;

  i = 0;

  /* Get addresses of frontend and backend */
  r = bud_config_str_to_addr(config->frontend.host,
                             config->frontend.port,
                             &config->frontend.addr);
  if (r != 0) {
    err = bud_error_num(kBudErrPton, r);
    goto fatal;
  }

  r = bud_config_str_to_addr(config->backend.host,
                             config->backend.port,
                             &config->backend.addr);
  if (r != 0) {
    err = bud_error_num(kBudErrPton, r);
    goto fatal;
  }

#ifndef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  if (config->context_count > 1) {
    err = bud_error(kBudErrSNINotSupported);
    goto fatal;
  }
#endif  /* !SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */

  /* Allocate workers */
  if (!config->is_worker) {
    config->workers = calloc(config->worker_count, sizeof(*config->workers));
    if (config->workers == NULL) {
      err = bud_error_str(kBudErrNoMem, "workers");
      goto fatal;
    }
  }

  /* Initialize logger */
  err = bud_logger_new(config);
  if (!bud_is_ok(err))
    goto fatal;

  /* Connect to redis */
  if (config->redis.enabled &&
      (config->is_worker || config->worker_count == 0)) {
    config->redis.ctx = bud_redis_new(config, &err);
    if (config->redis.ctx == NULL)
      goto fatal;
  }

  /* Load all contexts */
  for (i = 0; i < config->context_count; i++) {
    ctx = &config->contexts[i];

    err = bud_config_new_ssl_ctx(config, ctx);
    if (!bud_is_ok(err))
      goto fatal;

    if (!SSL_CTX_use_certificate_chain_file(ctx->ctx, ctx->cert_file)) {
      err = bud_error_str(kBudErrParseCert, ctx->cert_file);
      goto fatal;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx->ctx,
                                     ctx->key_file,
                                     SSL_FILETYPE_PEM)) {
      err = bud_error_str(kBudErrParseKey, ctx->key_file);
      goto fatal;
    }
  }

  return bud_ok();

fatal:
  /* Free all allocated contexts */
  do {
    bud_context_free(&config->contexts[i]);

    i--;
  } while (i >= 0);
  free(config->workers);
  config->workers = NULL;
  if (config->redis.ctx != NULL)
    bud_redis_free(config->redis.ctx);
  config->redis.ctx = NULL;
  if (config->logger != NULL)
    bud_logger_free(config);
  config->logger = NULL;

  return err;
}


#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
int bud_config_select_sni_context(SSL* s, int* ad, void* arg) {
  int i;
  bud_config_t* config;
  bud_context_t* ctx;
  const char* servername;

  config = arg;
  servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

  /* SNI redis */
  ctx = SSL_get_app_data(s);
  if (ctx != NULL) {
    SSL_set_SSL_CTX(s, ctx->ctx);
    return SSL_TLSEXT_ERR_OK;
  }

  /* No servername - no context selection */
  if (servername == NULL)
    return SSL_TLSEXT_ERR_OK;

  /* TODO(indutny): Binary search */
  for (i = 1; i < config->context_count; i++) {
    ctx = &config->contexts[i];

    if (strncasecmp(servername, ctx->servername, ctx->servername_len) != 0)
      break;
    SSL_set_SSL_CTX(s, ctx->ctx);
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
