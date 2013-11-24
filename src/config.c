#include <getopt.h>  /* getopt */
#include <stdio.h>  /* fprintf */
#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset, strlen, strncmp */

#include "uv.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "config.h"
#include "common.h"
#include "version.h"
#include "worker.h"

static bud_error_t bud_config_init(bud_config_t* config);
static void bud_config_set_defaults(bud_config_t* config);
static void bud_print_help(int argc, char** argv);
static void bud_print_version();
static void bud_config_print_default();
#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
static int bud_config_select_sni_context(SSL* s, int* ad, void* arg);
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */
#ifdef OPENSSL_NPN_NEGOTIATED
static int bud_config_advertise_next_proto(SSL* s,
                                           const unsigned char** data,
                                           unsigned int* len,
                                           void* arg);
#endif  /* OPENSSL_NPN_NEGOTIATED */


bud_config_t* bud_config_cli_load(int argc, char** argv, bud_error_t* err) {
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
        config = bud_config_load(optarg, err);
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

  *err = bud_ok();

  /* CLI options */
  if (config != NULL) {
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
  }

  return config;
}


bud_config_t* bud_config_load(const char* path, bud_error_t* err) {
  int i;
  int j;
  int npn_count;
  int context_count;
  JSON_Value* json;
  JSON_Value* val;
  JSON_Object* obj;
  JSON_Object* frontend;
  JSON_Object* backend;
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
  config->worker_count = (int) json_object_get_number(obj, "workers");
  config->restart_timeout = (int) json_object_get_number(obj,
                                                         "restart_timeout");

  frontend = json_object_get_object(obj, "frontend");
  if (frontend != NULL) {
    config->frontend.port = (uint16_t) json_object_get_number(frontend, "port");
    config->frontend.host = json_object_get_string(frontend, "host");
    val = json_object_get_value(frontend, "proxyline");
    if (val != NULL)
      config->frontend.proxyline = json_value_get_boolean(val);
    else
      config->frontend.proxyline = -1;
  }
  backend = json_object_get_object(obj, "backend");
  if (backend != NULL) {
    config->backend.port = (uint16_t) json_object_get_number(backend, "port");
    config->backend.host = json_object_get_string(backend, "host");
  }

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
    ctx->ciphers = json_object_get_string(obj, "ciphers");
    val = json_object_get_value(obj, "server_preference");
    if (val != NULL)
      ctx->server_preference = json_value_get_boolean(val);
    else
      ctx->server_preference = -1;
    ctx->npn = json_object_get_array(obj, "npn");

    /* Verify that all indexes are strings */
    if (ctx->npn != NULL) {
      npn_count = json_array_get_count(ctx->npn);
      for (j = 0; j < npn_count; j++) {
        if (json_value_get_type(json_array_get_value(ctx->npn, j)) !=
            JSONString) {
          *err = bud_error(kBudErrNPNNonString);
          goto failed_get_index;
        }
      }
    } else if (config->contexts[0].npn != NULL) {
      /* Inherit NPN from first context */
      ctx->npn = config->contexts[0].npn;
    }
  }
  config->context_count = context_count;

  bud_config_set_defaults(config);
  *err = bud_config_init(config);
  if (!bud_is_ok(*err)) {
    bud_config_free(config);
    return NULL;
  }

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

  for (i = 0; i < config->context_count; i++) {
    SSL_CTX_free(config->contexts[i].ctx);
    free(config->contexts[i].npn_line);
    config->contexts[i].npn_line = NULL;
  }
  free(config->workers);
  config->workers = NULL;

  json_value_free(config->json);
  config->json = NULL;
  free(config);
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
  bud_config_set_defaults(&config);

  fprintf(stdout, "{\n");
  fprintf(stdout, "  \"daemon\": false,\n");
  fprintf(stdout, "  \"workers\": %d,\n", config.worker_count);
  fprintf(stdout, "  \"restart_timeout\": %d,\n", config.restart_timeout);
  fprintf(stdout, "  \"frontend\": {\n");
  fprintf(stdout, "    \"port\": %d,\n", config.frontend.port);
  fprintf(stdout, "    \"host\": \"%s\",\n", config.frontend.host);
  fprintf(stdout, "    \"proxyline\": \"false\"\n");
  fprintf(stdout, "  },\n");
  fprintf(stdout, "  \"backend\": {\n");
  fprintf(stdout, "    \"port\": %d,\n", config.backend.port);
  fprintf(stdout, "    \"host\": \"%s\"\n", config.backend.host);
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
    if (ctx->ciphers != NULL)
      fprintf(stdout, "    \"ciphers\": \"%s\",\n", ctx->ciphers);
    else
      fprintf(stdout, "    \"ciphers\": null,\n");

    /* Sorry, hard-coded */
    fprintf(stdout, "    \"server_preference\": true,\n");
#ifdef OPENSSL_NPN_NEGOTIATED
    fprintf(stdout, "    \"npn\": [\"http/1.1\", \"http/1.0\"]\n");
#endif  /* OPENSSL_NPN_NEGOTIATED */

    if (i == config.context_count - 1)
      fprintf(stdout, "  }");
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

  DEFAULT(config->worker_count, 0, 1);
  DEFAULT(config->restart_timeout, 0, 250);
  DEFAULT(config->frontend.port, 0, 1443);
  DEFAULT(config->frontend.host, NULL, "0.0.0.0");
  DEFAULT(config->frontend.proxyline, -1, 0);
  DEFAULT(config->backend.port, 0, 8000);
  DEFAULT(config->backend.host, NULL, "127.0.0.1");
  DEFAULT(config->context_count, 0, 1);

  if (config->context_count == 0)
    config->context_count = 1;

  for (i = 0; i < config->context_count; i++) {
    DEFAULT(config->contexts[i].cert_file, NULL, "keys/cert.pem");
    DEFAULT(config->contexts[i].key_file, NULL, "keys/key.pem");
    DEFAULT(config->contexts[i].server_preference, -1, 1);
  }
}

#undef DEFAULT


bud_error_t bud_config_init(bud_config_t* config) {
  int i;
  bud_context_t* ctx;
  bud_error_t err;
#ifdef OPENSSL_NPN_NEGOTIATED
  int j;
  unsigned int offset;
  int npn_count;
  int npn_len;
  const char* npn;
#endif  /* OPENSSL_NPN_NEGOTIATED */

  i = 0;

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

  /* Load all contexts */
  for (i = 0; i < config->context_count; i++) {
    ctx = &config->contexts[i];

    ctx->ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx->ctx == NULL) {
      err = bud_error_str(kBudErrNoMem, "SSL_CTX");
      goto fatal;
    }

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

    SSL_CTX_set_session_cache_mode(ctx->ctx,
                                   SSL_SESS_CACHE_SERVER |
                                   SSL_SESS_CACHE_NO_INTERNAL |
                                   SSL_SESS_CACHE_NO_AUTO_CLEAR);
    if (ctx->ciphers != NULL)
      SSL_CTX_set_cipher_list(ctx->ctx, ctx->ciphers);
    if (ctx->server_preference)
      SSL_CTX_set_options(ctx->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
    if (config->context_count > 1) {
      SSL_CTX_set_tlsext_servername_callback(ctx->ctx,
                                             bud_config_select_sni_context);
      SSL_CTX_set_tlsext_servername_arg(ctx->ctx, config);
    }
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */

    if (ctx->npn != NULL) {
#ifdef OPENSSL_NPN_NEGOTIATED
      /* Calculate storage requirements */
      npn_count = json_array_get_count(ctx->npn);
      ctx->npn_line_len = 0;
      for (j = 0; j < npn_count; j++)
        ctx->npn_line_len += 1 + strlen(json_array_get_string(ctx->npn, j));

      ctx->npn_line = malloc(ctx->npn_line_len);
      if (ctx->npn_line == NULL) {
        err = bud_error_str(kBudErrNoMem, "NPN copy");
        goto fatal;
      }

      /* Fill npn line */
      for (j = 0, offset = 0; j < npn_count; j++) {
        npn = json_array_get_string(ctx->npn, j);
        npn_len = strlen(npn);

        ctx->npn_line[offset++] = npn_len;
        memcpy(ctx->npn_line + offset, npn, npn_len);
        offset += npn_len;
      }
      ASSERT(offset == ctx->npn_line_len, "NPN Line overflow");

      SSL_CTX_set_next_protos_advertised_cb(ctx->ctx,
                                            bud_config_advertise_next_proto,
                                            ctx);
#else  /* !OPENSSL_NPN_NEGOTIATED */
      err = bud_error(kBudErrNPNNotSupported);
      goto fatal;
#endif  /* OPENSSL_NPN_NEGOTIATED */
    }
  }

  return bud_ok();

fatal:
  /* Free all allocated contexts */
  do {
    SSL_CTX_free(config->contexts[i].ctx);
    free(config->contexts[i].npn_line);
    config->contexts[i].ctx = NULL;
    config->contexts[i].npn_line = NULL;

    i--;
  } while (i >= 0);

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

  /* No servername - no context selection */
  if (servername == NULL)
    return SSL_TLSEXT_ERR_OK;

  /* TODO(indutny): Binary search */
  for (i = 1; i < config->context_count; i++) {
    ctx = &config->contexts[i];

    if (strncmp(servername, ctx->servername, ctx->servername_len) != 0)
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
