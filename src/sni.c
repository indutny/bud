#include <stdlib.h>  /* NULL */

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "error.h"
#include "config.h"

static int SSL_CTX_use_certificate_chain(SSL_CTX *ctx, BIO *in);


/**
 * NOTE: From node.js
 *
 * Read a file that contains our certificate in "PEM" format,
 * possibly followed by a sequence of CA certificates that should be
 * sent to the peer in the Certificate message.
 *
 * Taken from OpenSSL - editted for style.
 */
int SSL_CTX_use_certificate_chain(SSL_CTX *ctx, BIO *in) {
  int ret;
  X509 *x;
  X509 *ca;
  int r;
  unsigned long err;

  ERR_clear_error();

  ret = 0;
  x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);

  if (x == NULL) {
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);

  if (ERR_peek_error() != 0) {
    /* Key/certificate mismatch doesn't imply ret==0 ... */
    ret = 0;
  }

  if (ret) {
    /**
     * If we could set up our certificate, now proceed to
     * the CA certificates.
     */
    if (ctx->extra_certs != NULL) {
      sk_X509_pop_free(ctx->extra_certs, X509_free);
      ctx->extra_certs = NULL;
    }

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
      r = SSL_CTX_add_extra_chain_cert(ctx, ca);

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
  if (x != NULL)
    X509_free(x);
  return ret;
}


bud_error_t bud_sni_from_json(bud_config_t* config,
                              struct json_value_t* json,
                              bud_context_t* ctx) {
  int r;
  JSON_Object* obj;
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
  ctx->servername = NULL;
  ctx->servername_len = 0;
  ctx->ciphers = json_object_get_string(obj, "ciphers");
  ctx->npn = json_object_get_array(obj, "npn");

  err = bud_config_new_ssl_ctx(config, ctx);
  if (!bud_is_ok(err))
    goto fatal;

  bio = BIO_new_mem_buf((void*) cert_str, strlen(cert_str));
  if (bio == NULL) {
    err = bud_error_str(kBudErrNoMem, "BIO_new_mem_buf");
    goto fatal;
  }

  r = SSL_CTX_use_certificate_chain(ctx->ctx, bio);
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
