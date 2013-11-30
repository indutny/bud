#include <stdlib.h>  /* NULL */
#include <string.h>  /* strlen */

#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "parson.h"

#include "ocsp.h"
#include "client.h"
#include "client-private.h"
#include "common.h"
#include "config.h"
#include "error.h"
#include "http-pool.h"

static void bud_client_stapling_cb(bud_http_request_t* req, bud_error_t err);

bud_error_t bud_client_ocsp_stapling(bud_client_t* client) {
  bud_config_t* config;
  bud_context_t* context;
  bud_error_t err;
  const char* url;
  size_t url_size;
  char* ocsp;
  size_t ocsp_size;

  config = client->config;

  if (client->sni_ctx.ctx != NULL) {
    /* Async SNI success */
    context = &client->sni_ctx;
  } else if (client->hello.servername_len != 0) {
    /* Matching context */
    context = bud_config_select_context(config,
                                        client->hello.servername,
                                        client->hello.servername_len);

    /* Cache context to prevent second search in OpenSSL's callback */
    if (context != NULL) {
      if (!SSL_set_ex_data(client->ssl, kBudSSLSNIIndex, context)) {
        err = bud_error(kBudErrStaplingSetData);
        goto fatal;
      }
    }
  } else {
    /* Default context */
    context = &config->contexts[0];
  }

  url = bud_context_get_ocsp(context, &url_size, &ocsp, &ocsp_size);

  /* Certificate has no OCSP url */
  if (url == NULL)
    return bud_ok();

  client->stapling_req = bud_http_post(config->stapling.pool,
                                       config->stapling.query_fmt,
                                       url,
                                       url_size,
                                       ocsp,
                                       ocsp_size,
                                       bud_client_stapling_cb,
                                       &err);
  free(ocsp);
  client->stapling_req->data = client;

  if (!bud_is_ok(err))
    goto fatal;

  client->hello_parse = kBudProgressRunning;
  return bud_ok();

fatal:
  return err;
}


void bud_client_stapling_cb(bud_http_request_t* req, bud_error_t err) {
  bud_client_t* client;
  bud_config_t* config;
  JSON_Object* obj;
  const char* b64_body;
  size_t b64_body_len;
  char* body;
  const unsigned char* pbody;
  size_t body_len;
  OCSP_RESPONSE* resp;
  int status;

  client = req->data;
  config = client->config;
  client->stapling_req = NULL;
  client->hello_parse = kBudProgressDone;

  if (!bud_is_ok(err)) {
    NOTICE(&client->frontend, "SNI cb failed: %d - \"%s\"", err.code, err.str);
    goto done;
  }

  /* Stapling backend failure - ignore */
  if (req->code != 200)
    goto done;

  obj = json_value_get_object(req->response);
  b64_body = json_object_get_string(obj, "response");
  if (b64_body == NULL)
    goto done;

  b64_body_len = strlen(b64_body);
  body_len = base64_decoded_size_fast(b64_body_len);
  body = malloc(body_len);
  if (body == NULL)
    goto done;

  body_len = base64_decode(body, body_len, b64_body, b64_body_len);
  pbody = (const unsigned char*) body;
  resp = d2i_OCSP_RESPONSE(NULL, &pbody, body_len);
  free(body);
  if (resp == NULL)
    goto done;

  /* Not successful response, do not waste bandwidth on it */
  status = OCSP_response_status(resp);
  OCSP_RESPONSE_free(resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    goto done;

  /* Set stapling! */
  SSL_set_tlsext_status_ocsp_resp(client->ssl, body, body_len);

  /* NOTE: Stapling failure should not prevent us from responding */
done:
  json_value_free(req->response);
  bud_client_cycle(client);
  return;
}
