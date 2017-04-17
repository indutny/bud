#include <stdlib.h>  /* NULL */
#include <limits.h>  /* ULLONG_MAX */

#ifndef _WIN32
#include <unistd.h>  /* getgid(), setgid() */
#include <sys/types.h>  /* uid_t, gid_t */
#include <pwd.h>  /* getpwnam */
#include <grp.h>  /* getgrnam */
#endif

#include "openssl/bio.h"
#include "openssl/engine.h"
#include "openssl/err.h"
#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include "parson.h"
#include "uv.h"

#include "src/config/utils.h"
#include "src/common.h"
#include "src/config.h"

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
  int r;
  unsigned long err;
  bud_context_pkey_type_t type;
  bud_context_pem_t* pem;

  ERR_clear_error();

  ret = 0;
  x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
  pem = NULL;

  if (x == NULL) {
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx->ctx, x);
  SSL_CTX_select_current_cert(ctx->ctx, x);
  type = bud_config_pkey_type(x->cert_info->key->pkey);

  pem = &ctx->pem[type];
  pem->cert = x;
  pem->issuer = NULL;

  if (ERR_peek_error() != 0) {
    /* Key/certificate mismatch doesn't imply ret==0 ... */
    ret = 0;
  }

  if (ret) {
    X509* ca;

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
      /*
       * Extra cert - add it to store to make OpenSSL pick and send proper
       * certs automatically
       */
      r = SSL_CTX_add0_chain_cert(ctx->ctx, ca);
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
      if (pem->issuer != NULL || X509_check_issued(ca, x) != X509_V_OK)
        continue;
      pem->issuer = ca;
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
    if (pem->issuer == NULL) {
      X509_STORE* store;
      X509_STORE_CTX store_ctx;

      store = SSL_CTX_get_cert_store(ctx->ctx);
      ret = X509_STORE_CTX_init(&store_ctx, store, NULL, NULL);
      if (!ret)
        goto fatal;

      ret = X509_STORE_CTX_get1_issuer(&pem->issuer, &store_ctx, pem->cert);
      X509_STORE_CTX_cleanup(&store_ctx);

      ret = ret < 0 ? 0 : 1;
      /* NOTE: get_cert_store doesn't increment reference count */
    } else {
      /* Increment issuer reference count */
      CRYPTO_add(&pem->issuer->references, 1, CRYPTO_LOCK_X509);
    }

    if (pem->issuer != NULL) {
      /* Get ocsp_id */
      pem->ocsp_id = OCSP_cert_to_id(NULL, pem->cert, pem->issuer);
      if (pem->ocsp_id == NULL)
        goto fatal;
    }
  }

fatal:
  if (!ret && pem != NULL && pem->issuer != NULL) {
    X509_free(pem->issuer);
    pem->issuer = NULL;
  }

  if (!(pem != NULL && pem->cert == x) && x != NULL)
    X509_free(x);

  return ret;
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
  else if (config->contexts[0].ca_store != NULL)
    store = config->contexts[0].ca_store;
  else
    store = NULL;

  /* No certificate store, validate cert if present */
  if (store == NULL) {
    if (cert != NULL)
      return SSL_get_verify_result(ssl) == X509_V_OK ? 1 : 0;
    else if (config->contexts[0].optional_cert)
      return 1;
    else
      return config->contexts[0].request_cert ? 1 : 0;
  }

  if (!X509_STORE_CTX_init(&store_ctx, store, cert, NULL))
    return 0;

  r = X509_verify_cert(&store_ctx);
  X509_STORE_CTX_cleanup(&store_ctx);

  return r;
}


bud_error_t bud_config_drop_privileges(bud_config_t* config) {
#ifndef _WIN32
  if (config->user != NULL) {
    struct passwd* p;

    p = getpwnam(config->user);
    if (p == NULL)
      return bud_error_dstr(kBudErrInvalidUser, config->user);

    if (setgid(p->pw_gid) != 0)
      return bud_error_num(kBudErrSetgid, errno);
    if (setuid(p->pw_uid) != 0)
      return bud_error_num(kBudErrSetuid, errno);
  } else if (config->group != NULL) {
    struct group* g;

    g = getgrnam(config->group);
    if (g == NULL)
      return bud_error_dstr(kBudErrInvalidGroup, config->group);

    if (setgid(g->gr_gid) != 0)
      return bud_error_num(kBudErrSetgid, errno);
  }
#endif  /* !_WIN32 */

  return bud_ok();
}


#define CSTRCMP(a, b) strncmp((a), b, sizeof(b) - 1)


bud_config_balance_t bud_config_balance_to_enum(const char* balance) {
  if (balance == NULL)
    return kBudBalanceRoundRobin;
  if (CSTRCMP(balance, "sni") == 0)
    return kBudBalanceSNI;
  else if (CSTRCMP(balance, "on-fail") == 0)
    return kBudBalanceOnFail;
  else
    return kBudBalanceRoundRobin;
}

#undef CSTRCMP


const char* bud_config_balance_to_str(bud_config_balance_t balance) {
  if (balance == kBudBalanceRoundRobin)
    return "roundrobin";
  else if (balance == kBudBalanceSNI)
    return "sni";
  else
    return "on-fail";
}


uint64_t bud_config_get_client_id(bud_config_t* config) {
  uint64_t r;

  r = config->client_id;
  if (r == ULLONG_MAX)
    config->client_id = 0;
  else
    config->client_id++;

  return r;
}


bud_context_pkey_type_t bud_config_pkey_type(EVP_PKEY* pkey) {
  if (pkey->type == EVP_PKEY_RSA)
    return kBudContextPKeyRSA;
  else if (pkey->type == EVP_PKEY_EC)
    return kBudContextPKeyECC;
  else
    UNEXPECTED;

  return kBudContextPKeyRSA;
}


/* This is kind of unfortunate, but I don't think there is a simpler way */
#define SSL_aECDSA 0x00000040L
SSL_CIPHER* ssl3_choose_cipher(SSL* ssl,
                               STACK_OF(SSL_CIPHER)* clnt,
                               STACK_OF(SSL_CIPHER)* srvr);


bud_context_pkey_type_t bud_context_select_pkey(bud_context_t* context,
                                                SSL* s) {
  SSL_SESSION* sess;
  const SSL_CIPHER* cipher;

  sess = SSL_get_session(s);
  if (sess == NULL)
    return kBudContextPKeyRSA;

  /* Use session cipher */
  cipher = sess->cipher;

  /* Select cipher */
  if (cipher == NULL)
    cipher = ssl3_choose_cipher(s, sess->ciphers, SSL_get_ciphers(s));

  if (cipher == NULL)
    return kBudContextPKeyRSA;

  if ((cipher->algorithm_auth & SSL_aECDSA) == SSL_aECDSA)
    return kBudContextPKeyECC;

  return kBudContextPKeyRSA;
}


#undef SSL_aECDSA


bud_error_t bud_config_load_file(bud_config_t* config,
                                 const char* path,
                                 const char** out) {
  bud_error_t err;
  char* content;

  /* Check if we already have cache entry */
  content = bud_hashmap_get(&config->files.hashmap, path, strlen(path));
  if (content != NULL) {
    *out = content;
    return bud_ok();
  }

  ASSERT(config->loop != NULL, "Loop should be present");
  err = bud_read_file_by_path(config->loop, path, &content);
  if (!bud_is_ok(err))
    return err;

  err = bud_hashmap_insert(&config->files.hashmap,
                           path,
                           strlen(path),
                           content);
  if (!bud_is_ok(err)) {
    free(content);
    return err;
  }

  *out = content;
  return bud_ok();
}


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
      return bud_error_str(kBudErrNoMem, "BIO_new_mem_buf:CA store bio");

    while ((x509 = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
      if (x509 == NULL) {
        err = bud_error_dstr(kBudErrParseCert, cert);
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
    return bud_error_dstr(kBudErrLoadCert, filename);

  x509 = NULL;
  *store = X509_STORE_new();
  if (*store == NULL) {
    err = bud_error_dstr(kBudErrNoMem, "CA store");
    goto fatal;
  }

  while ((x509 = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
    if (x509 == NULL) {
      err = bud_error_dstr(kBudErrParseCert, filename);
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
    return bud_error_dstr(kBudErrNonString, name);
  }

  return bud_ok();
}


#define FLAG_CHECK(STR, NAME, CAP_NAME)                                       \
    if (strncmp((STR), #NAME, sizeof(#NAME) - 1) == 0) {                      \
      res |= ENGINE_METHOD_##CAP_NAME;                                        \
      continue;                                                               \
    }


unsigned int bud_config_get_engine_flags(bud_config_t* config,
                                         const JSON_Array* flags) {
  int i;
  int count;
  unsigned int res;

  if (flags == NULL)
    return ENGINE_METHOD_ALL;

  res = 0;

  count = json_array_get_count(flags);
  for (i = 0; i < count; i++) {
    const char* flag;

    flag = json_array_get_string(flags, i);
    if (flag == NULL)
      continue;

    FLAG_CHECK(flag, rsa, RSA);
    FLAG_CHECK(flag, dsa, DSA);
    FLAG_CHECK(flag, dh, DH);
    FLAG_CHECK(flag, rand, RAND);
    FLAG_CHECK(flag, ecdh, ECDH);
    FLAG_CHECK(flag, ecdsa, ECDSA);
    FLAG_CHECK(flag, ciphers, CIPHERS);
    FLAG_CHECK(flag, digests, DIGESTS);
    FLAG_CHECK(flag, store, STORE);
    FLAG_CHECK(flag, pkey_meths, PKEY_METHS);
    FLAG_CHECK(flag, pkey_asn1_meths, PKEY_ASN1_METHS);
    FLAG_CHECK(flag, all, ALL);
  }

  return res;
}


bud_error_t bud_config_set_engine(bud_config_t* config,
                                  const char* name,
                                  unsigned int flags) {
  ENGINE* engine;
  int r;

  engine = ENGINE_by_id(name);

  // Engine not found, try loading dynamically
  if (engine == NULL) {
    engine = ENGINE_by_id("dynamic");
    if (engine != NULL) {
      if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", name, 0) ||
          !ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0)) {
        ENGINE_free(engine);
        engine = NULL;
      }
    }
  }

  if (engine == NULL) {
    int err = ERR_get_error();
    if (err == 0)
      return bud_error(kBudErrEngineNotFound);
    else
      return bud_error(kBudErrEngineLoad);
  }

  r = ENGINE_set_default(engine, flags);
  ENGINE_free(engine);
  if (r == 0)
    return bud_error(kBudErrEngineLoad);

  return bud_ok();
}
