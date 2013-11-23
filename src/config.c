#include <getopt.h>  /* getopt */
#include <stdio.h>  /* fprintf */
#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset, strlen, strncmp */

#include "openssl/err.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "config.h"
#include "common.h"
#include "version.h"

static bud_error_t bud_config_init(bud_config_t* config);
static void bud_config_set_defaults(bud_config_t* config);
static void bud_print_help(int argc, char** argv);
static void bud_print_version();
static void bud_config_print_default();
#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
static int bud_config_select_sni_context(SSL* s, int* ad, void* arg);
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */


bud_config_t* bud_config_cli_load(int argc, char** argv, bud_error_t* err) {
  int index;
  struct option long_options[] = {
    { "version", 0, NULL, 'v' },
    { "config", 1, NULL, 'c' },
    { "default-config", 0, NULL, 1001 },
    { NULL, 0, NULL, 0 }
  };

  index = 0;
  switch (getopt_long(argc, argv, "vc:", long_options, &index)) {
    case 'v':
      bud_print_version();
      break;
    case 'c':
      return bud_config_load(optarg, err);
    case 1001:
      bud_config_print_default();
      break;
    default:
      bud_print_help(argc, argv);
      break;
  }

  *err = bud_ok();
  return NULL;
}


bud_config_t* bud_config_load(const char* path, bud_error_t* err) {
  int i;
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

  for (i = 0; i < config->context_count; i++)
    SSL_CTX_free(config->contexts[i].ctx);
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
  fprintf(stdout, "\n");
}


void bud_print_version() {
  fprintf(stdout, "bud %d.%d\n", BUD_VERSION_MAJOR, BUD_VERSION_MINOR);
}


void bud_config_print_default() {
  int i;
  bud_config_t config;
  bud_context_t* ctx;

  memset(&config, 0, sizeof(config));
  bud_config_set_defaults(&config);

  fprintf(stdout, "{\n");
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
    fprintf(stdout, "    \"server_preference\": true\n");

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

  i = 0;

#ifndef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  if (config->context_count > 1) {
    err = bud_error(kBudErrSNINotSupported);
    goto fatal;
  }
#endif  /* !SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */

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
  }

  return bud_ok();

fatal:
  /* Free all allocated contexts */
  do {
    SSL_CTX_free(config->contexts[i].ctx);
    config->contexts[i].ctx = NULL;

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
