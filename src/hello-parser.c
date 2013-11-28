#include <stdint.h>  /* uint8_t */
#include <stdlib.h>  /* NULL */
#include <string.h>  /* memset */

#include "hello-parser.h"
#include "error.h"

typedef struct bud_parser_state_s bud_parser_state_t;
typedef enum frame_type_e frame_type_t;
typedef enum handshake_type_e handshake_type_t;
typedef enum extension_type_e extension_type_t;

struct bud_parser_state_s {
  size_t frame_len;
  size_t body_offset;
  size_t extension_offset;

  bud_client_hello_t* hello;
};

enum frame_type_e {
  kChangeCipherSpec = 20,
  kAlert = 21,
  kHandshake = 22,
  kApplicationData = 23,
  kOther = 255
};

enum handshake_type_e {
  kClientHello = 1
};

enum extension_type_e {
  kServername = 0,
  kTLSSessionTicket = 35
};

static const size_t kMaxTLSFrameLen = 16 * 1024 + 5;
static const uint8_t kServernameHostname = 0;

static bud_error_t bud_parse_record_header(const uint8_t* data,
                                           size_t size,
                                           bud_parser_state_t* state);
static bud_error_t bud_parse_header(const uint8_t* data,
                                    size_t size,
                                    bud_parser_state_t* state);
static bud_error_t bud_parse_tls_client_hello(const uint8_t* data,
                                              size_t size,
                                              bud_parser_state_t* state);
static bud_error_t bud_parse_extension(extension_type_t type,
                                       const uint8_t* data,
                                       size_t size,
                                       bud_parser_state_t* state);

bud_error_t bud_parse_client_hello(const char* data,
                                   size_t size,
                                   bud_client_hello_t* hello) {
  bud_parser_state_t state;
  bud_error_t err;

  state.hello = hello;

  err = bud_parse_record_header((const uint8_t*) data, size, &state);
  if (!bud_is_ok(err))
    return err;

  return bud_parse_header((const uint8_t*) data, size, &state);
}


bud_error_t bud_parse_record_header(const uint8_t* data,
                                    size_t size,
                                    bud_parser_state_t* state) {
  /* >= 5 bytes for header parsing */
  if (size < 5)
    return bud_error(kBudErrParserNeedMore);

  if (data[0] == kChangeCipherSpec ||
      data[0] == kAlert ||
      data[0] == kHandshake ||
      data[0] == kApplicationData) {
    state->frame_len = (data[3] << 8) + data[4];
    state->body_offset = 5;
  } else {
    return bud_error_str(kBudErrParserErr, "Unknown record type");
  }

  /*
   * Sanity check (too big frame, or too small)
   * Let OpenSSL handle it
   */
  if (state->frame_len >= kMaxTLSFrameLen)
    return bud_error_str(kBudErrParserErr, "Record length OOB");

  return bud_ok();
}


bud_error_t bud_parse_header(const uint8_t* data,
                             size_t size,
                             bud_parser_state_t* state) {
  bud_error_t err;

  /* >= 5 + frame size bytes for frame parsing */
  if (state->body_offset + state->frame_len > size)
    return bud_error(kBudErrParserNeedMore);

  if (data[state->body_offset] == kClientHello) {
    /* Clear hello, just in case if we will return bud_ok() ;) */
    memset(state->hello, 0, sizeof(*state->hello));

    err = bud_parse_tls_client_hello(data, size, state);
    if (!bud_is_ok(err))
      return err;

    /* Check if we overflowed (do not reply with any private data) */
    if (state->hello->session == NULL ||
        state->hello->session_len > 32 ||
        state->hello->session + state->hello->session_len >
            (const char*) data + size) {
      return bud_error_str(kBudErrParserErr, "Session id overflow");
    }
  } else {
    return bud_error_str(kBudErrParserErr, "Unexpected first record");
  }

  return bud_ok();
}


bud_error_t bud_parse_tls_client_hello(const uint8_t* data,
                                       size_t size,
                                       bud_parser_state_t* state) {
  bud_error_t err;
  const uint8_t* body;
  size_t session_offset;
  size_t cipher_offset;
  uint16_t cipher_len;
  size_t comp_offset;
  uint8_t comp_len;
  size_t extension_offset;
  size_t ext_off;
  uint16_t ext_type;
  uint16_t ext_len;

  /* Skip frame header, hello header, protocol version and random data */
  session_offset = state->body_offset + 4 + 2 + 32;
  if (session_offset + 1 >= size)
    return bud_error_str(kBudErrParserErr, "Header OOB");

  body = data + session_offset;
  state->hello->session_len = *body;
  state->hello->session = (const char*) body + 1;

  cipher_offset = session_offset + 1 + state->hello->session_len;
  if (cipher_offset + 1 >= size)
    return bud_error_str(kBudErrParserErr, "Session OOB");

  cipher_len = (data[cipher_offset] << 8) + data[cipher_offset + 1];
  comp_offset = cipher_offset + 2 + cipher_len;
  if (comp_offset > size)
    return bud_error_str(kBudErrParserErr, "Cipher suite OOB");

  comp_len = data[comp_offset];
  extension_offset = comp_offset + 1 + comp_len;
  if (extension_offset > size)
    return bud_error_str(kBudErrParserErr, "Compression methods OOB");

  /* No extensions present */
  if (extension_offset == size)
    return bud_ok();

  ext_off = extension_offset + 2;

  // Parse known extensions
  while (ext_off < size) {
    // Extension OOB
    if (ext_off + 4 > size)
      return bud_error_str(kBudErrParserErr, "Extension header OOB");

    ext_type = (data[ext_off] << 8) + data[ext_off + 1];
    ext_len = (data[ext_off + 2] << 8) + data[ext_off + 3];
    ext_off += 4;

    // Extension OOB
    if (ext_off + ext_len > size)
      return bud_error_str(kBudErrParserErr, "Extension body OOB");

    err = bud_parse_extension((extension_type_t) ext_type,
                              data + ext_off,
                              ext_len,
                              state);
    if (!bud_is_ok(err))
      return err;

    ext_off += ext_len;
  }

  // Extensions OOB failure
  if (ext_off > size)
    return bud_error_str(kBudErrParserErr, "Extensions OOB");

  return bud_ok();
}


bud_error_t bud_parse_extension(extension_type_t type,
                                const uint8_t* data,
                                size_t size,
                                bud_parser_state_t* state) {
  uint32_t server_names_len;
  size_t offset;
  uint8_t name_type;
  uint16_t name_len;

  switch (type) {
    case kServername:
      if (size < 2)
        return bud_error_str(kBudErrParserErr, "Servername ext is too small");

      server_names_len = (data[0] << 8) + data[1];
      if (server_names_len + 2 > size)
        return bud_error_str(kBudErrParserErr, "Servername ext OOB");

      for (offset = 2; offset < 2 + server_names_len; ) {
        if (offset + 3 > size)
          return bud_error_str(kBudErrParserErr, "Servername name OOB");

        name_type = data[offset];
        if (name_type != kServernameHostname)
          return bud_error_str(kBudErrParserErr, "Servername type unexpected");

        name_len = (data[offset + 1] << 8) + data[offset + 2];
        offset += 3;
        if (offset + name_len > size)
          return bud_error_str(kBudErrParserErr, "Servername value OOB");

        state->hello->servername = (const char*) data + offset;
        state->hello->servername_len = name_len;
        offset += name_len;
      }
      break;
    case kTLSSessionTicket:
      state->hello->ticket_len = size;
      state->hello->ticket = (const char*) data + size;
      break;
    default:
      /* Ignore */
      break;
  }

  return bud_ok();
}
