#include <stdlib.h>
#include <string.h>

#include "openssl/ocsp.h"

#include "config/ocsp.h"
#include "common.h"
#include "config.h"

const char* bud_context_get_ocsp_id(bud_context_t* context,
                                    bud_context_pkey_type_t type,
                                    size_t* size) {
  char* encoded;
  unsigned char* pencoded;
  size_t encoded_len;
  char* base64;
  size_t base64_len;
  bud_context_pem_t* pem;

  pem = &context->pem[type];

  if (pem->ocsp_id == NULL)
    return NULL;

  base64 = NULL;
  encoded = NULL;
  /* Return cached id */
  if (pem->ocsp_der_id != NULL)
    goto done;

  encoded_len = i2d_OCSP_CERTID(pem->ocsp_id, NULL);
  base64_len = bud_base64_encoded_size(encoded_len);
  encoded = malloc(encoded_len);
  base64 = malloc(base64_len);
  if (encoded == NULL || base64 == NULL)
    goto done;

  pencoded = (unsigned char*) encoded;
  i2d_OCSP_CERTID(pem->ocsp_id, &pencoded);

  bud_base64_encode(encoded, encoded_len, base64, base64_len);
  pem->ocsp_der_id = base64;
  pem->ocsp_der_id_len = base64_len;
  base64 = NULL;

done:
  free(encoded);
  free(base64);
  *size = pem->ocsp_der_id_len;
  return pem->ocsp_der_id;
}


const char* bud_context_get_ocsp_req(bud_context_t* context,
                                     bud_context_pkey_type_t type,
                                     size_t* size,
                                     char** ocsp_request,
                                     size_t* ocsp_request_len) {
  STACK_OF(OPENSSL_STRING)* urls;
  OCSP_REQUEST* req;
  OCSP_CERTID* id;
  char* encoded;
  unsigned char* pencoded;
  size_t encoded_len;
  bud_context_pem_t* pem;

  urls = NULL;
  id = NULL;
  encoded = NULL;

  pem = &context->pem[type];

  /* Cached url */
  if (pem->ocsp_url != NULL)
    goto has_url;

  urls = X509_get1_ocsp(pem->cert);
  if (urls == NULL)
    goto done;

  pem->ocsp_url = sk_OPENSSL_STRING_pop(urls);
  pem->ocsp_url_len = strlen(pem->ocsp_url);

has_url:
  if (pem->ocsp_url == NULL)
    goto done;

  id = OCSP_CERTID_dup(pem->ocsp_id);
  if (id == NULL)
    goto done;

  /* Create request */
  req = OCSP_REQUEST_new();
  if (req == NULL)
    goto done;
  if (!OCSP_request_add0_id(req, id))
    goto done;
  id = NULL;

  encoded_len = i2d_OCSP_REQUEST(req, NULL);
  encoded = malloc(encoded_len);
  if (encoded == NULL)
    goto done;

  pencoded = (unsigned char*) encoded;
  i2d_OCSP_REQUEST(req, &pencoded);
  OCSP_REQUEST_free(req);

  *ocsp_request = encoded;
  *ocsp_request_len = encoded_len;
  encoded = NULL;

done:
  if (id != NULL)
    OCSP_CERTID_free(id);
  if (urls != NULL)
    X509_email_free(urls);
  if (encoded != NULL)
    free(encoded);

  *size = pem->ocsp_url_len;
  return pem->ocsp_url;
}
