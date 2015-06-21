#include <stdlib.h>  /* NULL */
#include <string.h>  /* strlen */

#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "src/ocsp.h"
#include "src/client.h"
#include "src/client-common.h"
#include "src/common.h"
#include "src/config.h"
#include "src/error.h"
#include "src/http-pool.h"

static void bud_client_stapling_cache_req_cb(bud_http_request_t* req,
                                             bud_error_t err);
static void bud_client_stapling_req_cb(bud_http_request_t* req,
                                       bud_error_t err);
static int bud_client_staple_json(bud_client_t* client, JSON_Value* json);

bud_error_t bud_client_ocsp_stapling(bud_client_t* client) {
  bud_config_t* config;
  bud_context_t* context;
  bud_error_t err;
  const char* id;
  size_t id_size;
  bud_context_pkey_type_t type;

  config = client->config;

  if (client->sni_ctx.ctx != NULL) {
    /* Async SNI success */
    context = &client->sni_ctx;
  } else if (client->hello.servername_len != 0) {
    /* Matching context */
    context = bud_config_select_context(config,
                                        client->hello.servername,
                                        client->hello.servername_len);
  } else {
    /* Default context */
    context = &config->contexts[0];
  }

  type = bud_context_select_pkey(context, client->ssl);
  client->stapling_type = type;

  /* Cache context to prevent second search in OpenSSL's callback */
  if (!SSL_set_ex_data(client->ssl, kBudSSLSNIIndex, context)) {
    err = bud_error(kBudErrStaplingSetData);
    goto fatal;
  }

  id = bud_context_get_ocsp_id(context, type, &id_size);

  /* Certificate has no OCSP id */
  if (id == NULL) {
    DBG_LN(&client->backend, "stapling id missing");
    return bud_ok();
  }

  /* Request backend for cached respose first */
  client->stapling_cache_req = bud_http_get(config->stapling.pool,
                                            config->stapling.url,
                                            id,
                                            id_size,
                                            bud_client_stapling_cache_req_cb,
                                            &err);
  client->stapling_cache_req->data = client;

  if (!bud_is_ok(err))
    goto fatal;

  client->async_hello = kBudProgressRunning;
  return bud_ok();

fatal:
  return err;
}


void bud_client_stapling_cache_req_cb(bud_http_request_t* req,
                                      bud_error_t err) {
  bud_client_t* client;
  bud_client_error_t cerr;
  bud_config_t* config;
  bud_context_t* context;
  const char* id;
  size_t id_size;
  const char* url;
  size_t url_size;
  char* ocsp;
  size_t ocsp_size;
  char* json;
  size_t json_size;
  size_t offset;
  bud_context_pkey_type_t type;

  client = req->data;
  config = client->config;
  type = client->stapling_type;
  context = SSL_get_ex_data(client->ssl, kBudSSLSNIIndex);

  client->async_hello = kBudProgressDone;
  client->stapling_cache_req = NULL;
  json = NULL;
  ocsp = NULL;

  ASSERT(context != NULL, "Context disappeared");

  if (!bud_is_ok(err)) {
    WARNING(&client->frontend,
            "OCSP cache cb failed: \"%s\"",
            bud_error_to_str(err));
    goto done;
  }

  /* Cache hit, success */
  if ((req->code >= 200 && req->code < 400) &&
      bud_client_staple_json(client, req->response) == 0) {
    DBG_LN(&client->frontend, "stapling cache hit");
    goto done;
  }

  DBG_LN(&client->frontend, "stapling cache miss");
  id = bud_context_get_ocsp_id(context, type, &id_size);
  url = bud_context_get_ocsp_req(context, type, &url_size, &ocsp, &ocsp_size);

  /* Certificate has no OCSP url */
  if (url == NULL)
    goto done;

  /* Format JSON request */
  json_size = 2 + bud_base64_encoded_size(ocsp_size) + 2 + url_size;
  json_size += /* "ocsp": */ 7 + /* "url": */ 6 + /* {,}\0 */ 4;
  json = malloc(json_size);
  if (json == NULL)
    goto done;

  offset = snprintf(json,
                    json_size,
                    "{\"url\":\"%.*s\",\"ocsp\":\"",
                    (int) url_size,
                    url);
  bud_base64_encode(ocsp, ocsp_size, json + offset, json_size - offset);
  offset += bud_base64_encoded_size(ocsp_size);
  snprintf(json + offset, json_size - offset, "\"}");

  /* Request OCSP response */
  client->stapling_req = bud_http_post(config->stapling.pool,
                                       config->stapling.url,
                                       id,
                                       id_size,
                                       json,
                                       json_size - 1,
                                       bud_client_stapling_req_cb,
                                       &err);
  client->stapling_req->data = client;

  if (!bud_is_ok(err))
    goto done;

  client->async_hello = kBudProgressRunning;

done:
  free(ocsp);
  free(json);
  json_value_free(req->response);
  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    return bud_client_close(client, cerr);
}


void bud_client_stapling_req_cb(bud_http_request_t* req, bud_error_t err) {
  bud_client_t* client;
  bud_client_error_t cerr;

  client = req->data;
  client->stapling_req = NULL;
  client->async_hello = kBudProgressDone;

  if (!bud_is_ok(err)) {
    WARNING(&client->frontend,
            "OCSP cb failed: \"%s\"",
            bud_error_to_str(err));
    goto done;
  }

  /* Stapling backend failure - ignore */
  if (req->code < 200 || req->code >= 400) {
    DBG_LN(&client->frontend, "stapling request failure");
    goto done;
  }
  DBG_LN(&client->frontend, "stapling request success");

  /* Note, ignoring return value here */
  (void) bud_client_staple_json(client, req->response);

  /* NOTE: Stapling failure should not prevent us from responding */
done:
  json_value_free(req->response);
  cerr = bud_client_cycle(client);
  if (!bud_is_ok(cerr.err))
    return bud_client_close(client, cerr);
}


int bud_client_staple_json(bud_client_t* client, JSON_Value* json) {
  JSON_Object* obj;
  const char* b64_body;
  size_t b64_body_len;
  char* body;
  const unsigned char* pbody;
  size_t body_len;
  OCSP_RESPONSE* resp;
  int status;
  int r;

  r = -1;
  body = NULL;

  obj = json_value_get_object(json);
  b64_body = json_object_get_string(obj, "response");
  if (b64_body == NULL)
    goto done;

  b64_body_len = strlen(b64_body);
  body_len = bud_base64_decoded_size_fast(b64_body_len);
  body = malloc(body_len);
  if (body == NULL)
    goto done;

  body_len = bud_base64_decode(body, body_len, b64_body, b64_body_len);
  pbody = (const unsigned char*) body;
  resp = d2i_OCSP_RESPONSE(NULL, &pbody, body_len);
  if (resp == NULL)
    goto done;

  /* Not successful response, do not waste bandwidth on it */
  status = OCSP_response_status(resp);
  OCSP_RESPONSE_free(resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    goto done;

  /* Set stapling! */
  client->stapling_ocsp_resp = body;
  client->stapling_ocsp_resp_len = body_len;
  body = NULL;
  r = 0;

done:
  free(body);
  return r;
}


int bud_client_stapling_cb(SSL* ssl, void* arg) {
  bud_client_t* client;

  client = SSL_get_ex_data(ssl, kBudSSLClientIndex);
  if (client == NULL || client->stapling_ocsp_resp == NULL)
    return SSL_TLSEXT_ERR_NOACK;

  SSL_set_tlsext_status_ocsp_resp(ssl,
                                  client->stapling_ocsp_resp,
                                  client->stapling_ocsp_resp_len);
  client->stapling_ocsp_resp = NULL;
  return SSL_TLSEXT_ERR_OK;
}
