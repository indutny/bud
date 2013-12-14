#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <stdio.h>
#include <stdlib.h>

typedef enum bud_client_side_type_e bud_client_side_type_t;

enum bud_client_side_type_e {
  kBudFrontend,
  kBudBackend
};

#define ASSERT__COMMON(expr, desc, ...)                                       \
    do {                                                                      \
      if (!(expr)) {                                                          \
        fprintf(stderr, desc "\n", __VA_ARGS__);                              \
        abort();                                                              \
      }                                                                       \
    } while (0)

#define ASSERT_VA(expr, desc, ...)                                            \
    ASSERT__COMMON(expr,                                                      \
                   "Assertion failed %s:%d\n" desc,                           \
                   __FILE__,                                                  \
                   __LINE__,                                                  \
                   __VA_ARGS__)

#define ASSERT(expr, desc)                                                    \
    ASSERT__COMMON(expr,                                                      \
                   "Assertion failed %s:%d\n" desc,                           \
                   __FILE__,                                                  \
                   __LINE__)

#define UNEXPECTED ASSERT(0, "Unexpected")

#define container_of(ptr, type, member) \
    ((type *) ((char *) (ptr) - offsetof(type, member)))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

size_t bud_base64_decode(char *buf,
                         size_t len,
                         const char *src,
                         const size_t srcLen);
size_t bud_base64_decoded_size_fast(size_t size);

#define bud_base64_encoded_size(size) ((size + 2 - ((size + 2) % 3)) / 3 * 4)
size_t bud_base64_encode(const char* src,
                         size_t slen,
                         char* dst,
                         size_t dlen);

const char* bud_side_str(bud_client_side_type_t side);
const char* bud_sslerror_str(int err);

#endif  /* SRC_COMMON_H_ */
