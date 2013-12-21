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
  int r;
  JSON_Object* obj;
  JSON_Object* tmp;
  const char* cert_str;
  const char* key_str;
  bud_error_t err;
  BIO* bio;
  EVP_PKEY* key;

  obj = json_value_get_object(json);
  cert_str = json_object_get_string(obj, "cert");
  key_str = json_object_get_string(obj, "key");
  if (obj == NULL || cert_str == NULL || key_str == NULL) {
    err = bud_error_str(kBudErrJSONParse, "<SNI Response>");
    goto fatal;
  }

  /* Load NPN from response */
  memset(ctx, 0, sizeof(*ctx));
  ctx->ciphers = json_object_get_string(obj, "ciphers");
  ctx->ecdh = json_object_get_string(obj, "ecdh");
  ctx->npn = json_object_get_array(obj, "npn");
  tmp = json_object_get_object(obj, "backend");
  if (tmp != NULL) {
    ctx->backend = &ctx->backend_st;
    bud_config_load_backend(config, tmp, ctx->backend);
  }

  err = bud_config_new_ssl_ctx(config, ctx);
  if (!bud_is_ok(err))
    goto fatal;

  bio = BIO_new_mem_buf((void*) cert_str, strlen(cert_str));
  if (bio == NULL) {
    err = bud_error_str(kBudErrNoMem, "BIO_new_mem_buf");
    goto fatal;
  }

  r = bud_context_use_certificate_chain(ctx, bio);
  BIO_free_all(bio);
  if (!r) {
    err = bud_error_str(kBudErrParseCert, "<SNI>");
    goto fatal;
  }

  bio = BIO_new_mem_buf((void*) key_str, strlen(key_str));
  if (bio == NULL) {
    err = bud_error_str(kBudErrNoMem, "BIO_new_mem_buf");
    goto fatal;
  }

  key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free_all(bio);
  if (key == NULL) {
    err = bud_error_str(kBudErrNoMem, "EVP_PKEY");
    goto fatal;
  }

  r = SSL_CTX_use_PrivateKey(ctx->ctx, key);
  EVP_PKEY_free(key);
  if (!r) {
    err = bud_error_str(kBudErrParseKey, "<SNI>");
    goto fatal;
  }

  return bud_ok();

fatal:
  if (!bud_is_ok(err)) {
    SSL_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
  }
  return err;
}
