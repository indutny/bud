#include "key-ex.h"
#include "client.h"
#include "http-pool.h"

#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "parson.h"
#include <string.h>

static void bud_client_key_ex_cb(bud_http_request_t* req, bud_error_t err);

bud_error_t bud_client_handle_key_ex(struct bud_client_s* client) {
  SSL* ssl;
  bud_config_t* config;
  bud_error_t err;
  const char* servername;
  char body[10240];
  size_t bodysz;
  const char* md;
  const char* type;

  config = client->config;
  if (!config->key_ex.enabled)
    return bud_error(kBudErrKeyExSkip);

  ssl = client->ssl;
  if (!SSL_want_rsa_decrypt(ssl) && !SSL_want_sign(ssl))
    return bud_error(kBudErrKeyExSkip);

  /* Already running */
  if (client->key_ex_req != NULL)
    return bud_ok();

  servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (servername == NULL)
    servername = "";

  /* Populate JSON */
  if (SSL_get_key_ex_md(ssl) == 0)
    md = "none";
  else
    md = OBJ_nid2sn(SSL_get_key_ex_md(ssl));

  if (SSL_want_rsa_decrypt(ssl) || SSL_get_key_ex_type(ssl) == EVP_PKEY_RSA)
    type = "rsa";
  else if (SSL_get_key_ex_type(ssl) == EVP_PKEY_EC)
    type = "ec";
  else if (SSL_get_key_ex_type(ssl) == EVP_PKEY_DSA)
    type = "dsa";
  else
    type = "unknown";

  bodysz = 0;
  bodysz += snprintf(body,
                     sizeof(body) - bodysz,
                     "{\"type\":\"%s\",\"md\":\"%s\",\"key\":\"%s\","
                        "\"data\":\"",
                     SSL_want_sign(ssl) ? "sign" : "decrypt",
                     md,
                     type);
  bodysz += bud_base64_encode((char*) SSL_get_key_ex_data(ssl),
                              SSL_get_key_ex_len(ssl),
                              body + bodysz,
                              sizeof(body) - bodysz);
  bodysz += snprintf(body + bodysz,
                     sizeof(body) - bodysz,
                     "\"}");
  if (bodysz >= (sizeof(body) - 1))
    return bud_error_str(kBudErrNoMem, "key_ex JSON");

  client->key_ex_req = bud_http_post(config->key_ex.pool,
                                     config->key_ex.url,
                                     servername,
                                     strlen(servername),
                                     body,
                                     bodysz,
                                     bud_client_key_ex_cb,
                                     &err);
  client->key_ex_req->data = client;
  if (!bud_is_ok(err)) {
    NOTICE(&client->frontend,
           "failed to request Key Ex: \"%s\"",
           bud_error_to_str(err));
    return err;
  }

  return bud_ok();
}


void bud_client_key_ex_cb(bud_http_request_t* req, bud_error_t err) {
  bud_client_t* client;
  bud_client_error_t cerr;
  JSON_Object* obj;
  const char* b64_resp;
  size_t b64_respsz;
  char resp[10240];
  size_t respsz;

  client = req->data;
  client->key_ex_req = NULL;

  if (!bud_is_ok(err)) {
    WARNING(&client->frontend,
            "Key Ex cb failed: \"%s\"",
            bud_error_to_str(err));
    goto fatal;
  }


  obj = json_value_get_object(req->response);
  b64_resp = json_object_get_string(obj, "response");
  if (b64_resp == NULL) {
    err = bud_error(kBudErrKeyExNoResponse);
    goto fatal;
  }
  b64_respsz = strlen(b64_resp);
  respsz = bud_base64_decoded_size_fast(b64_respsz);
  if (respsz >= sizeof(resp)) {
    err = bud_error(kBudErrKeyExResponseOOB);
    goto fatal;
  }

  respsz = bud_base64_decode(resp, sizeof(resp), b64_resp, b64_respsz);

  /* Set key ex data! */
  if (!SSL_supply_key_ex_data(client->ssl, (unsigned char*) resp, respsz)) {
    err = bud_error(kBudErrKeyExSupply);
    goto fatal;
  }

  if (!SSL_accept(client->ssl)) {
    err = bud_error(kBudErrKeyExSupply);
    goto fatal;
  }

  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    bud_client_close(client, cerr);

  return;

fatal:
  bud_client_close(client, bud_client_error(err, &client->frontend));
}
