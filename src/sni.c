#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset */

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "error.h"
#include "config.h"


bud_error_t bud_sni_from_json(bud_config_t* config,
                              struct json_value_t* json,
                              bud_context_t* ctx) {
  JSON_Object* obj;
  JSON_Value* val;
  const char* cert_str;
  const char* key_str;
  const char* pass_str;
  JSON_Array* cert_strs;
  JSON_Array* key_strs;
  JSON_Array* pass_strs;
  bud_error_t err;

  cert_str = NULL;
  key_str = NULL;
  pass_str = NULL;
  cert_strs = NULL;
  key_strs = NULL;
  pass_strs = NULL;

  obj = json_value_get_object(json);
  val = json_object_get_value(obj, "cert");
  if (json_value_get_type(val) == JSONString)
    cert_str = json_value_get_string(val);
  else
    cert_strs = json_value_get_array(val);
  val = json_object_get_value(obj, "key");
  if (json_value_get_type(val) == JSONString)
    key_str = json_value_get_string(val);
  else
    key_strs = json_value_get_array(val);
  val = json_object_get_value(obj, "passphrase");
  if (json_value_get_type(val) == JSONString)
    pass_str = json_value_get_string(val);
  else
    pass_strs = json_value_get_array(val);

  if (obj == NULL ||
      !((cert_str != NULL && key_str != NULL) ||
        (cert_strs != NULL && key_strs != NULL))) {
    err = bud_error_str(kBudErrJSONParse, "<SNI Response>");
    goto fatal;
  }

  /* Load NPN from response */
  memset(ctx, 0, sizeof(*ctx));
  ctx->cert_file = cert_str;
  ctx->key_file = key_str;
  ctx->key_pass = pass_str;
  ctx->cert_files = cert_strs;
  ctx->key_files = key_strs;
  ctx->key_passes = pass_strs;
  ctx->ciphers = json_object_get_string(obj, "ciphers");
  ctx->ecdh = json_object_get_string(obj, "ecdh");
  ctx->ticket_key = json_object_get_string(obj, "ticket_key");
  ctx->npn = json_object_get_array(obj, "npn");
  ctx->ca_array = json_object_get_array(obj, "ca");
  val = json_object_get_value(obj, "request_cert");
  if (val != NULL)
    ctx->request_cert = json_value_get_boolean(val);
  err = bud_config_load_backend_list(config, obj, &ctx->backend);
  if (!bud_is_ok(err))
    goto fatal;

  err = bud_context_init(config, ctx);

  /* Make sure that deallocated values won't be used */
  ctx->cert_file = NULL;
  ctx->key_file = NULL;
  ctx->key_pass = NULL;
  ctx->cert_files = NULL;
  ctx->key_files = NULL;
  ctx->key_passes = NULL;
  ctx->ticket_key = NULL;
  if (!bud_is_ok(err))
    goto fatal;

  return bud_ok();

fatal:
  if (!bud_is_ok(err)) {
    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
  }
  free(ctx->backend.list);
  ctx->backend.list = NULL;
  return err;
}
