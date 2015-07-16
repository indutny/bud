#include <string.h>
#include <stdlib.h>

#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "uv.h"

#include "src/config/context.h"
#include "src/client.h"
#include "src/client-common.h"
#include "src/common.h"
#include "src/config.h"
#include "src/config/ticket.h"
#include "src/ocsp.h"


#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
static int bud_config_select_sni_context(SSL* s, int* ad, void* arg);
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */
#ifdef OPENSSL_NPN_NEGOTIATED
static char* bud_config_encode_npn(bud_config_t* config,
                                   const JSON_Array* npn,
                                   size_t* len,
                                   bud_error_t* err);
static int bud_config_advertise_npn(SSL* s,
                                    const unsigned char** data,
                                    unsigned int* len,
                                    void* arg);
static int bud_config_select_alpn(SSL* ssl,
                                  const unsigned char** out,
                                  unsigned char* outlen,
                                  const unsigned char* in,
                                  unsigned int inlen,
                                  void* arg);
#endif  /* OPENSSL_NPN_NEGOTIATED */


bud_error_t bud_context_load(JSON_Object* obj, bud_context_t* ctx) {
  bud_error_t err;
  JSON_Value* val;

  err = bud_ok();

  ctx->server_preference = -1;

  ctx->servername = json_object_get_string(obj, "servername");
  ctx->servername_len = ctx->servername == NULL ? 0 : strlen(ctx->servername);
  ctx->cert_file = json_object_get_string(obj, "cert");
  ctx->cert_files = json_object_get_array(obj, "cert");
  ctx->key_file = json_object_get_string(obj, "key");
  ctx->key_files = json_object_get_array(obj, "key");
  ctx->key_pass = json_object_get_string(obj, "passphrase");
  ctx->key_passes = json_object_get_array(obj, "passphrase");
  ctx->npn = json_object_get_array(obj, "npn");
  ctx->ciphers = json_object_get_string(obj, "ciphers");
  ctx->ecdh = json_object_get_string(obj, "ecdh");
  ctx->dh_file = json_object_get_string(obj, "dh");
  ctx->ticket_key = json_object_get_string(obj, "ticket_key");
  val = json_object_get_value(obj, "ticket_timeout");
  if (val != NULL)
    ctx->ticket_timeout = json_value_get_number(val);
  else
    ctx->ticket_timeout = -1;
  val = json_object_get_value(obj, "ticket_rotate");
  if (val != NULL)
    ctx->ticket_rotate = json_value_get_number(val);
  else
    ctx->ticket_rotate = -1;
  ctx->ca_file = json_object_get_string(obj, "ca");
  ctx->ca_array = json_object_get_array(obj, "ca");
  ctx->balance = json_object_get_string(obj, "balance");

  val = json_object_get_value(obj, "request_cert");
  if (val != NULL)
    ctx->request_cert = json_value_get_boolean(val);
  else
    ctx->request_cert = 0;
  val = json_object_get_value(obj, "optional_cert");
  if (val != NULL)
    ctx->optional_cert = json_value_get_boolean(val);
  else
    ctx->optional_cert = 0;
  val = json_object_get_value(obj, "server_preference");
  if (val != NULL)
    ctx->server_preference = json_value_get_boolean(val);
  else
    ctx->server_preference = 1;

  if (ctx->ca_array != NULL)
    err = bud_config_load_ca_arr(&ctx->ca_store, ctx->ca_array);
  else if (ctx->ca_file != NULL)
    err = bud_config_load_ca_file(&ctx->ca_store, ctx->ca_file);
  if (!bud_is_ok(err))
    return err;

  err = bud_config_verify_all_strings(ctx->npn, "npn");
  if (!bud_is_ok(err))
    return err;

  return bud_ok();
}


void bud_context_free(bud_context_t* context) {
  int i;

  if (context == NULL)
    return;

  for (i = 0; i < context->backend.count; i++) {
    if (context->backend.list[i].revive_timer != NULL) {
      /* Let the timer now that the backend is gone at this point */
      context->backend.list[i].revive_timer->data = NULL;
      uv_close((uv_handle_t*) context->backend.list[i].revive_timer,
               (uv_close_cb) free);
      context->backend.list[i].revive_timer = NULL;
    }
  }

  bud_hashmap_destroy(&context->backend.external_map);

  SSL_CTX_free(context->ctx);
  for (i = 0; i < kBudContextPKeyEnd; i++) {
    bud_context_pem_t* pem = &context->pem[i];
    if (pem->cert != NULL)
      X509_free(pem->cert);
    if (pem->issuer != NULL)
      X509_free(pem->issuer);
    if (pem->ocsp_id != NULL)
      OCSP_CERTID_free(pem->ocsp_id);
    free(pem->ocsp_der_id);

    pem->cert = NULL;
    pem->issuer = NULL;
    pem->ocsp_id = NULL;
    pem->ocsp_der_id = NULL;
  }

  if (context->ca_store != NULL)
    X509_STORE_free(context->ca_store);
  if (context->dh != NULL)
    DH_free(context->dh);
  free(context->backend.list);
  free(context->npn_line);

  context->ctx = NULL;
  context->ca_store = NULL;
  context->npn_line = NULL;
  context->dh = NULL;
  context->backend.list = NULL;
  context->backend.count = 0;

  if (context->rotate_timer != NULL) {
    uv_close((uv_handle_t*) context->rotate_timer, (uv_close_cb) free);
    context->rotate_timer = NULL;
  }
}


bud_error_t bud_context_load_cert(bud_context_t* context,
                                  const char* cert_file) {
  bud_error_t err;
  BIO* cert_bio;
  const char* content;
  int r;

  err = bud_config_load_file(context->config, cert_file, &content);
  if (bud_is_ok(err))
    cert_bio = BIO_new_mem_buf((void*) content, strlen(content));
  /* Hm... not a file, let's try parsing it as a raw string */
  else
    cert_bio = BIO_new_mem_buf((void*) cert_file, strlen(cert_file));
  if (cert_bio == NULL)
    return bud_error_str(kBudErrNoMem, "BIO_new_mem_buf:cert");

  r = bud_context_use_certificate_chain(context, cert_bio);
  BIO_free_all(cert_bio);
  if (!r)
    return bud_error_dstr(kBudErrParseCert, cert_file);

  return bud_ok();
}


bud_error_t bud_context_load_key(bud_context_t* context,
                                 const char* key_file,
                                 const char* key_pass) {
  bud_error_t err;
  BIO* key_bio;
  EVP_PKEY* pkey;
  int r;
  const char* content;

  err = bud_config_load_file(context->config, key_file, &content);
  if (bud_is_ok(err))
    key_bio = BIO_new_mem_buf((void*) content, strlen(content));
  /* Hm... not a file, let's try parsing it as a raw string */
  else
    key_bio = BIO_new_mem_buf((void*) key_file, strlen(key_file));
  if (key_bio == NULL)
    return bud_error_str(kBudErrNoMem, "BIO_new_mem_buf:key");

  pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, (void*) key_pass);
  BIO_free_all(key_bio);
  if (pkey == NULL)
    return bud_error_dstr(kBudErrParseKey, key_file);

  r = SSL_CTX_use_PrivateKey(context->ctx, pkey);
  EVP_PKEY_free(pkey);
  if (!r)
    return bud_error_str(kBudErrLoadKey, "key doesn't match certificate");

  return bud_ok();
}


bud_error_t bud_context_load_keys(bud_context_t* context) {
  bud_error_t err;
  int i;
  int count;

  err = bud_ok();

  /* Drop all existing extra certs */
  if (context->ctx->extra_certs != NULL) {
    sk_X509_pop_free(context->ctx->extra_certs, X509_free);
    context->ctx->extra_certs = NULL;
  }

  /* Key file or string */
  if (context->key_file != NULL) {
    err = bud_context_load_key(context, context->key_file, context->key_pass);

  /* Key array */
  } else if (context->key_files != NULL &&
             json_array_get_count(context->key_files) != 0) {
    count = json_array_get_count(context->key_files);
    for (i = 0; i < count; i++) {
      err = bud_context_load_key(
          context,
          json_array_get_string(context->key_files, i),
          json_array_get_string(context->key_passes, i));
      if (!bud_is_ok(err))
        break;
    }
  } else {
    err = bud_error_str(kBudErrLoadKey, "no file was specified");
  }
  if (!bud_is_ok(err))
    goto fatal;

  /* Load cert file or string */
  if (context->cert_file != NULL) {
    err = bud_context_load_cert(context, context->cert_file);
  /* Load cert array */
  } else if (context->cert_files != NULL &&
             json_array_get_count(context->cert_files) != 0) {
    count = json_array_get_count(context->cert_files);
    for (i = 0; i < count; i++) {
      err = bud_context_load_cert(
          context,
          json_array_get_string(context->cert_files, i));
      if (!bud_is_ok(err))
        break;
    }
  } else {
    err = bud_error_str(kBudErrLoadCert, "no file was specified");
  }

fatal:
  return err;
}


bud_error_t bud_context_init(bud_config_t* config,
                             bud_context_t* context) {
  SSL_CTX* ctx;
  int ecdh_nid;
  EC_KEY* ecdh;
  bud_error_t err;
  int options;
  bud_context_t* ticket_context;

  context->config = config;

  if (context->ticket_key != NULL) {
    err = bud_context_set_ticket(context,
                                 context->ticket_key,
                                 strlen(context->ticket_key),
                                 kBudEncodingBase64);
    if (!bud_is_ok(err))
      return err;
  }

  /* Choose method, tlsv1_2 by default */
  if (config->frontend.method == NULL) {
    if (strcmp(config->frontend.security, "tls1.1") == 0)
      config->frontend.method = TLSv1_1_server_method();
    else if (strcmp(config->frontend.security, "tls1.0") == 0)
      config->frontend.method = TLSv1_server_method();
    else if (strcmp(config->frontend.security, "tls1.2") == 0)
      config->frontend.method = TLSv1_2_server_method();
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

  if (context->ticket_key_on)
    ticket_context = context;
  else if (config->contexts[0].ticket_key_on)
    ticket_context = &config->contexts[0];
  else
    ticket_context = NULL;

  if (ticket_context != NULL) {
    SSL_CTX_set_tlsext_ticket_keys(ctx,
                                   ticket_context->ticket_key_storage,
                                   sizeof(ticket_context->ticket_key_storage));
  }
  if (context->ticket_timeout != -1)
    SSL_CTX_set_timeout(ctx, context->ticket_timeout);
  else if (config->contexts[0].ticket_timeout != -1)
    SSL_CTX_set_timeout(ctx, config->contexts[0].ticket_timeout);

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
  if (config->contexts[0].request_cert || context->request_cert) {
    int flags;

    flags = SSL_VERIFY_PEER;
    if (!(config->contexts[0].optional_cert || context->optional_cert))
      flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(ctx, flags, bud_config_verify_cert);
  } else {
    /* Just verify anything */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, bud_config_verify_cert);
  }

  /* Use default ECDH curve */
  if (context->ecdh == NULL)
    context->ecdh = "prime256v1";

  /* ECDH curve selection */
  ecdh_nid = OBJ_sn2nid(context->ecdh);
  if (ecdh_nid == NID_undef) {
    err = bud_error_dstr(kBudErrECDHNotFound, context->ecdh);
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

  /* DH params */
  if (context->dh_file != NULL) {
    BIO* dh_bio;
    DH* dh;
    int r;
    const char* content;

    err = bud_config_load_file(context->config, context->dh_file, &content);
    if (!bud_is_ok(err)) {
      err = bud_error_dstr(kBudErrLoadDH, context->dh_file);
      goto fatal;
    }

    dh_bio = BIO_new_mem_buf((void*) content, strlen(content));
    if (dh_bio == NULL) {
      err = bud_error_str(kBudErrNoMem, "BIO_new_mem_buf:DH");
      goto fatal;
    }

    dh = PEM_read_bio_DHparams(dh_bio, NULL, NULL, NULL);
    BIO_free_all(dh_bio);
    if (dh == NULL) {
      err = bud_error_dstr(kBudErrParseDH, context->dh_file);
      goto fatal;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    r = SSL_CTX_set_tmp_dh(ctx, dh);
    if (context == &config->contexts[0])
      context->dh = dh;
    else
      DH_free(dh);
    if (r < 0) {
      err = bud_error_dstr(kBudErrParseDH, context->dh_file);
      goto fatal;
    }

  /* Use shared DH params */
  } else if (config->contexts[0].dh != NULL) {
    int r;

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    r = SSL_CTX_set_tmp_dh(ctx, config->contexts[0].dh);
    if (r < 0) {
      err = bud_error_dstr(kBudErrParseDH, config->contexts[0].dh_file);
      goto fatal;
    }
  }

  /* Cipher suites */
  if (context->ciphers != NULL)
    SSL_CTX_set_cipher_list(ctx, context->ciphers);
  else if (config->contexts[0].ciphers != NULL)
    SSL_CTX_set_cipher_list(ctx, config->contexts[0].ciphers);

  /* Disable SSL2/SSL3 */
  options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL;

  /* Do not resume session on renegotiation */
  options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

  if (context->server_preference)
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
                                          bud_config_advertise_npn,
                                          context);
    SSL_CTX_set_alpn_select_cb(ctx,
                               bud_config_select_alpn,
                               context);
  }
#else  /* !OPENSSL_NPN_NEGOTIATED */
  err = bud_error(kBudErrNPNNotSupported);
  goto fatal;
#endif  /* OPENSSL_NPN_NEGOTIATED */

  SSL_CTX_set_tlsext_status_cb(ctx, bud_client_stapling_cb);

  context->balance_e = bud_config_balance_to_enum(context->balance);
  if (context->balance_e == kBudBalanceSNI) {
    err = bud_error_dstr(kBudErrInvalidBalance, context->balance);
    goto fatal;
  }

  if (context->ticket_rotate != 0) {
    int r;

    context->rotate_timer = malloc(sizeof(*context->rotate_timer));
    if (context->rotate_timer == NULL) {
      err = bud_error_str(kBudErrNoMem, "rotate_timer");
      goto fatal;
    }

    r = uv_timer_init(context->config->loop, context->rotate_timer);
    if (r != 0) {
      err = bud_error_num(kBudErrRotateTimer, r);
      goto fatal;
    }

    context->rotate_timer->data = context;

    r = uv_timer_start(context->rotate_timer,
                       bud_context_rotate_cb,
                       context->ticket_rotate * 1000,
                       context->ticket_rotate * 1000);
    if (r != 0) {
      err = bud_error_num(kBudErrRotateTimer, r);
      goto fatal;
    }
  }

  context->ctx = ctx;
  /* Load keys and certs */
  return bud_context_load_keys(context);

fatal:
  SSL_CTX_free(ctx);
  return err;
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
    bud_client_t* client;

    client = SSL_get_ex_data(s, kBudSSLClientIndex);
    ASSERT(client != NULL, "Unexpected absence of client");

    SSL_set_SSL_CTX(s, ctx->ctx);
    s->options = ctx->ctx->options;
    s->verify_mode = ctx->ctx->verify_mode;
    SSL_set_cert_cb(s, bud_client_ssl_cert_cb, client);
    if (!SSL_set_ex_data(s, kBudSSLSNIIndex, ctx))
      return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  return SSL_TLSEXT_ERR_OK;
}
#endif  /* SSL_CTRL_SET_TLSEXT_SERVERNAME_CB */


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
    npn = config->contexts[0].npn;
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


int bud_config_advertise_npn(SSL* s,
                             const unsigned char** data,
                             unsigned int* len,
                             void* arg) {
  bud_context_t* context;

  context = arg;

  *data = (const unsigned char*) context->npn_line;
  *len = context->npn_line_len;

  return SSL_TLSEXT_ERR_OK;
}


int bud_config_select_alpn(SSL* ssl,
                           const unsigned char** out,
                           unsigned char* outlen,
                           const unsigned char* in,
                           unsigned int inlen,
                           void* arg) {
  bud_context_t* context;
  unsigned int in_off;
  size_t npn_off;

  context = arg;

  /* Select first protocol preferred by the server */

  npn_off = 0;
  while (npn_off < context->npn_line_len) {
    uint8_t npn_proto_len;
    const char* npn_proto;

    npn_proto_len = (uint8_t) context->npn_line[npn_off];
    npn_off++;
    npn_proto = &context->npn_line[npn_off];

    in_off = 0;
    while (in_off < inlen) {
      uint8_t in_proto_len;
      const char* in_proto;

      in_proto_len = (uint8_t) in[in_off];
      in_off++;
      in_proto = (const char*) &in[in_off];

      if (npn_proto_len != in_proto_len)
        continue;

      if (memcmp(npn_proto, in_proto, npn_proto_len) != 0)
        continue;

      *out = (const unsigned char*) npn_proto;
      *outlen = npn_proto_len;
      return SSL_TLSEXT_ERR_OK;
    }
  }

  *out = NULL;
  *outlen = 0;
  return SSL_TLSEXT_ERR_NOACK;
}
#endif  /* OPENSSL_NPN_NEGOTIATED */
