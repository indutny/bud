#include <stdint.h>
#include "openssl/ssl.h"

#include "common.h"
#include "error.h"

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

static const off_t BUF_STEP_LEN = 1024;

size_t bud_base64_decode(char* buf,
                         size_t len,
                         const char* src,
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
  /* We know how much we'll write, just make sure that there's space. */
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


#define BUD_MURMUR3_C1 0xcc9e2d51
#define BUD_MURMUR3_C2 0x1b873593


static uint32_t bud_murmur3(const char* key, uint32_t len) {
  uint32_t hash;
  const uint32_t* chunks;
  int chunk_count;
  int i;
  uint32_t tail;

  hash = 0;

  /* FIXME(indutny): this leads to unaligned loads for some keys */
  chunks = (const uint32_t*) key;
  chunk_count = len / 4;
  for (i = 0; i < chunk_count; i++) {
    uint32_t k;

    k = chunks[i];
    k *= BUD_MURMUR3_C1;
    k = (k << 15) | (k >> 17);
    k *= BUD_MURMUR3_C2;

    hash ^= k;
    hash = (hash << 13) | (hash >> 19);
    hash *= 5;
    hash += 0xe6546b64;
  }

  tail = 0;
  chunk_count *= 4;
  for (i = len - 1; i >= chunk_count; i--) {
    tail <<= 8;
    tail += key[i];
  }
  if (tail != 0) {
    tail *= BUD_MURMUR3_C1;
    tail = (tail << 15) | (tail >> 17);
    tail *= BUD_MURMUR3_C2;

    hash ^= tail;
  }

  hash ^= len;

  hash ^= hash >> 16;
  hash *= 0x85ebca6b;
  hash ^= hash >> 13;
  hash *= 0xc2b2ae35;
  hash ^= hash >> 16;

  return hash;
}


#undef BUD_MURMUR3_C1
#undef BUD_MURMUR3_C2


bud_error_t bud_hashmap_init(bud_hashmap_t* hashmap, unsigned int size) {
  hashmap->size = size;
  hashmap->space = calloc(size, sizeof(*hashmap->space));
  if (hashmap->space == NULL)
    return bud_error_str(kBudErrNoMem, "bud_hashmap_item_t");

  return bud_ok();
}


void bud_hashmap_destroy(bud_hashmap_t* hashmap) {
  if (hashmap->space == NULL)
    return;

  free(hashmap->space);
  hashmap->space = NULL;
}


/* A bit sparse, but should be fast */
#define BUD_HASHMAP_MAX_ITER 3
#define BUD_HASHMAP_GROW_DELTA 1024


static bud_hashmap_item_t* bud_hashmap_get_int(bud_hashmap_t* hashmap,
                                               const char* key,
                                               unsigned int key_len,
                                               int insert) {
  do {
    uint32_t i;
    uint32_t iter;
    bud_hashmap_item_t* space;
    unsigned int size;
    bud_hashmap_t old_map;

    i = bud_murmur3(key, key_len) % hashmap->size;
    for (iter = 0;
         iter < BUD_HASHMAP_MAX_ITER;
         iter++, i = (i + 1) % hashmap->size) {
      if (hashmap->space[i].key == NULL)
        break;
      if (!insert) {
        if (hashmap->space[i].key_len == key_len &&
            memcmp(hashmap->space[i].key, key, key_len) == 0) {
          break;
        }
      }
    }

    if (!insert && hashmap->space[i].key == NULL)
      return NULL;

    /* Found a spot */
    if (iter != BUD_HASHMAP_MAX_ITER)
      return &hashmap->space[i];

    /* No match */
    if (!insert)
      return NULL;

    /* Grow and retry */
    size = hashmap->size += BUD_HASHMAP_GROW_DELTA;
    space = calloc(size, sizeof(*space));
    if (space == NULL)
      return NULL;

    /* Rehash */
    old_map = *hashmap;
    hashmap->space = space;
    hashmap->size = size;
    for (i = 0; i < old_map.size; i++) {
      bud_hashmap_item_t* item;
      bud_error_t err;

      item = &old_map.space[i];
      err = bud_hashmap_insert(hashmap, item->key, item->key_len, item->value);
      if (!bud_is_ok(err)) {
        free(space);
        *hashmap = old_map;
        return NULL;
      }
    }

  /* Retry */
  } while (1);
}


#undef BUD_HASHMAP_GROW_DELTA
#undef BUD_HASHMAP_MAX_ITER


bud_error_t bud_hashmap_insert(bud_hashmap_t* hashmap,
                               const char* key,
                               unsigned int key_len,
                               void* value) {
  bud_hashmap_item_t* item;

  item = bud_hashmap_get_int(hashmap, key, key_len, 1);
  if (item == NULL)
    return bud_error_str(kBudErrNoMem, "bud_hashmap_t space");

  item->key = key;
  item->key_len = key_len;
  item->value = value;

  return bud_ok();
}


void* bud_hashmap_get(bud_hashmap_t* hashmap,
                      const char* key,
                      unsigned int key_len) {
  bud_hashmap_item_t* item;

  item = bud_hashmap_get_int(hashmap, key, key_len, 0);
  if (item == NULL)
    return NULL;

  return item->value;
}


bud_error_t bud_hashmap_iterate(bud_hashmap_t* hashmap,
                                bud_hashmap_iterate_cb cb,
                                void* arg) {
  bud_error_t err;
  unsigned int i;

  if (hashmap->space == NULL)
    return bud_ok();

  for (i = 0; i < hashmap->size; i++) {
    if (hashmap->space[i].key != NULL) {
      err = cb(&hashmap->space[i], arg);
      if (!bud_is_ok(err))
        return err;
    }
  }

  return bud_ok();
}


bud_error_t bud_read_file_by_path(uv_loop_t* loop,
                                  const char* path,
                                  char** out) {
  int r;
  uv_file file;
  bud_error_t err;
  uv_fs_t req;

  r = uv_fs_open(loop, &req, path, O_RDONLY, 0, NULL);
  file = req.result;
  uv_fs_req_cleanup(&req);

  if (r < 0)
    return bud_error_dstr(kBudErrLoadFile, path);

  err = bud_read_file_by_fd(loop, file, out);
  uv_fs_close(loop, &req, file, NULL);
  uv_fs_req_cleanup(&req);
  return err;
}


bud_error_t bud_read_file_by_fd(uv_loop_t* loop, uv_file fd, char** out) {
  ssize_t r;
  char* tmp;
  char* buffer;
  off_t offset;
  off_t buffer_len;
  bud_error_t err;

  buffer_len = BUF_STEP_LEN;
  buffer = malloc(buffer_len);

  if (buffer == NULL) {
    err = bud_error_str(kBudErrNoMem, "read_file_fd");
    goto read_failed;
  }

  offset = 0;

  while (1) {
    uv_fs_t req;
    uv_buf_t buf;

    buf = uv_buf_init(buffer + offset, buffer_len - offset);
    r = uv_fs_read(loop, &req, fd, &buf, 1, -1, NULL);
    uv_fs_req_cleanup(&req);

    if (r < 0) {
      err = bud_error_num(kBudErrFSRead, r);
      goto read_failed;
    } else if (req.result == 0) { /* EOF Encountered */
      break;
    } else {
      offset += req.result;

      if (offset >= buffer_len) {
        buffer_len += BUF_STEP_LEN;
        tmp = realloc(buffer, buffer_len);
        if (tmp == NULL) {
          err = bud_error_str(kBudErrNoMem, "attempt_realloc");
          goto read_failed;
        }

        buffer = tmp;
      }
    }
  }

  buffer[offset] = '\0';
  *out = buffer;

  return bud_ok();

read_failed:
  if (buffer != NULL)
    free(buffer);

  return err;
}


void bud_write_uint32(void* mem, uint32_t value, off_t offset) {
  uint8_t* d;

  d = (uint8_t*) ((char*) mem + offset);
  d[0] = (value >> 24) & 0xff;
  d[1] = (value >> 16) & 0xff;
  d[2] = (value >> 8) & 0xff;
  d[3] = value & 0xff;
}


uint32_t bud_read_uint32(void* mem, off_t offset) {
  uint8_t* d;

  d = (uint8_t*) ((char*) mem + offset);
  return (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
}
