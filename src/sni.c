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
  bud_error_t err;

  obj = json_value_get_object(json);
  cert_str = json_object_get_string(obj, "cert");
  key_str = json_object_get_string(obj, "key");
  if (obj == NULL || cert_str == NULL || key_str == NULL) {
    err = bud_error_str(kBudErrJSONParse, "<SNI Response>");
    goto fatal;
  }

  /* Load NPN from response */
  memset(ctx, 0, sizeof(*ctx));
  ctx->cert_str = cert_str;
  ctx->key_str = key_str;
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
