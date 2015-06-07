#ifndef SRC_CONFIG_UTILS_H_
#define SRC_CONFIG_UTILS_H_

#include "openssl/bio.h"
#include "openssl/x509.h"

#include "parson.h"

#include "src/config.h"
#include "src/common.h"

int bud_context_use_certificate_chain(bud_context_t* ctx, BIO *in);
int bud_config_verify_cert(int status, X509_STORE_CTX* s);
bud_config_balance_t bud_config_balance_to_enum(const char* balance);

bud_error_t bud_config_load_file(bud_config_t* config,
                                 const char* path,
                                 const char** out);
void bud_config_load_addr(JSON_Object* obj,
                          bud_config_addr_t* addr);
bud_error_t bud_config_load_ca_arr(X509_STORE** store,
                                   const JSON_Array* ca);
bud_error_t bud_config_load_ca_file(X509_STORE** store,
                                    const char* filename);

bud_error_t bud_config_verify_all_strings(const JSON_Array* npn,
                                          const char* name);

#endif  /* SRC_CONFIG_UTILS_H_ */
