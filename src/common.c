#include <stdint.h>
#include "openssl/ssl.h"

#include "common.h"

/**
 * NOTE:
 *
 * Copied from node.js
 */

/* supports regular and URL-safe base64 */
static const int unbase64_table[] =
  { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
  };
#define unbase64(x) unbase64_table[(uint8_t)(x)]


size_t bud_base64_decode(char *buf,
                         size_t len,
                         const char *src,
                          const size_t srcLen) {
  char a, b, c, d;
  char* dst;
  char* dstEnd;
  const char* srcEnd;
  int remaining;

  dst = buf;
  dstEnd = buf + len;
  srcEnd = src + srcLen;

  while (src < srcEnd && dst < dstEnd) {
    remaining = srcEnd - src;

    while (unbase64(*src) < 0 && src < srcEnd) src++, remaining--;
    if (remaining == 0 || *src == '=') break;
    a = unbase64(*src++);

    while (unbase64(*src) < 0 && src < srcEnd) src++, remaining--;
    if (remaining <= 1 || *src == '=') break;
    b = unbase64(*src++);

    *dst++ = (a << 2) | ((b & 0x30) >> 4);
    if (dst == dstEnd) break;

    while (unbase64(*src) < 0 && src < srcEnd) src++, remaining--;
    if (remaining <= 2 || *src == '=') break;
    c = unbase64(*src++);

    *dst++ = ((b & 0x0F) << 4) | ((c & 0x3C) >> 2);
    if (dst == dstEnd) break;

    while (unbase64(*src) < 0 && src < srcEnd) src++, remaining--;
    if (remaining <= 3 || *src == '=') break;
    d = unbase64(*src++);

    *dst++ = ((c & 0x03) << 6) | (d & 0x3F);
  }

  return dst - buf;
}


/* Doesn't check for padding at the end.  Can be 1-2 bytes over. */
size_t bud_base64_decoded_size_fast(size_t size) {
  size_t remainder;

  remainder = size % 4;

  size = (size / 4) * 3;
  if (remainder) {
    if (size == 0 && remainder == 1) {
      /* special case: 1-byte input cannot be decoded */
      size = 0;
    } else {
      /* non-padded input, add 1 or 2 extra bytes */
      size += 1 + (remainder == 3);
    }
  }

  return size;
}


size_t bud_base64_encode(const char* src,
                         size_t slen,
                         char* dst,
                         size_t dlen) {
  // We know how much we'll write, just make sure that there's space.
  ASSERT(dlen >= bud_base64_encoded_size(slen),
         "not enough space provided for base64 encode");

  dlen = bud_base64_encoded_size(slen);

  unsigned a;
  unsigned b;
  unsigned c;
  unsigned i;
  unsigned k;
  unsigned n;

  static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz"
                              "0123456789+/";

  i = 0;
  k = 0;
  n = slen / 3 * 3;

  while (i < n) {
    a = src[i + 0] & 0xff;
    b = src[i + 1] & 0xff;
    c = src[i + 2] & 0xff;

    dst[k + 0] = table[a >> 2];
    dst[k + 1] = table[((a & 3) << 4) | (b >> 4)];
    dst[k + 2] = table[((b & 0x0f) << 2) | (c >> 6)];
    dst[k + 3] = table[c & 0x3f];

    i += 3;
    k += 4;
  }

  if (n != slen) {
    switch (slen - n) {
      case 1:
        a = src[i + 0] & 0xff;
        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[(a & 3) << 4];
        dst[k + 2] = '=';
        dst[k + 3] = '=';
        break;

      case 2:
        a = src[i + 0] & 0xff;
        b = src[i + 1] & 0xff;
        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[((a & 3) << 4) | (b >> 4)];
        dst[k + 2] = table[(b & 0x0f) << 2];
        dst[k + 3] = '=';
        break;
    }
  }

  return dlen;
}


const char* bud_sslerror_str(int err) {
  switch (err) {
    case SSL_ERROR_SSL:
      return "SSL";
    case SSL_ERROR_WANT_READ:
      return "WANT_READ";
    case SSL_ERROR_WANT_WRITE:
      return "WANT_WRITE";
    case SSL_ERROR_WANT_X509_LOOKUP:
      return "WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
      return "SYSCALL";
    case SSL_ERROR_ZERO_RETURN:
      return "ZERO_RETURN";
    case SSL_ERROR_WANT_CONNECT:
      return "WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
      return "WANT_ACCEPT";
    default:
      return "UKNOWN";
  }
}


const char* bud_side_str(bud_client_side_type_t side) {
  if (side == kBudFrontend)
    return "frontend";
  else
    return "backend";
}
