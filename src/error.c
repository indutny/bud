#include <stdio.h>
#include <stdlib.h>

#include "openssl/err.h"
#include "uv.h"

#include "error.h"
#include "config.h"
#include "common.h"
#include "logger.h"

bud_error_t bud_ok() {
  return bud_error(kBudOk);
}


int bud_is_ok(bud_error_t err) {
  return err.code == kBudOk;
}


bud_error_t bud_error(bud_error_code_t code) {
  return bud_error_str(code, NULL);
}


bud_error_t bud_error_str(bud_error_code_t code, const char* str) {
  bud_error_t err;

  err.code = code;
  err.str = str;
  err.ret = 0;
  return err;
}


bud_error_t bud_error_dstr(bud_error_code_t code, const char* str) {
  bud_error_t err;
  static char st[1024];

  if (str != NULL) {
    strncpy(st, str, sizeof(st));
    err.str = st;
  } else {
    err.str = NULL;
  }

  err.code = code;
  err.ret = 0;
  return err;
}


bud_error_t bud_error_num(bud_error_code_t code, int ret) {
  bud_error_t err;

  err.code = code;
  err.str = NULL;
  err.ret = ret;
  return err;
}

#define BUD_ERROR_HANDLER(err)                                                \
  switch (err.code) {                                                         \
    case kBudOk:                                                              \
      BUD_ERROR("?! No error ?!")                                             \
    case kBudErrNoMem:                                                        \
      BUD_ERROR("Allocation failed: %s", err.str)                             \
    case kBudErrJSONParse:                                                    \
      BUD_ERROR("Failed to load or parse JSON: %s", err.str)                  \
    case kBudErrJSONNonObjectRoot:                                            \
      BUD_ERROR("Invalid json, root should be an object")                     \
    case kBudErrJSONNonObjectCtx:                                             \
      BUD_ERROR("Invalid json, each context should be an object")             \
    case kBudErrLoadCert:                                                     \
      BUD_ERROR("Failed to load cert %s reason: %s",                          \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrParseCert:                                                    \
      BUD_ERROR("Failed to load/parse cert %s reason: %s",                    \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrLoadKey:                                                      \
      BUD_ERROR("Failed to load key %s, reason: %s",                          \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrParseKey:                                                     \
      BUD_ERROR("Failed to load/parse key %s reason: %s",                     \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrSNINotSupported:                                              \
      BUD_ERROR("SNI not supported, but multiple contexts were given")        \
    case kBudErrNonString:                                                    \
      BUD_ERROR("%s array should contain only strings", err.str)              \
    case kBudErrNPNNotSupported:                                              \
      BUD_ERROR("NPN not supported, but present in config")                   \
    case kBudErrExePath:                                                      \
      BUD_UV_ERROR("uv_exe_path()", err)                                      \
    case kBudErrECDHNotFound:                                                 \
      BUD_ERROR("ECDH curve \"%s\" not found", err.str)                       \
    case kBudErrNoBackend:                                                    \
      BUD_ERROR("Empty \"backend\" array, or \"backend\" is not array")       \
    case kBudErrNoSSLIndex:                                                   \
      BUD_ERROR("SSL_get_ex_new_index failed")                                \
    case kBudErrSmallTicketKey:                                               \
      BUD_ERROR("ticket_key should decode into 48 byte sequence")             \
    case kBudErrAddCert:                                                      \
      BUD_ERROR("X509_STORE_add_cert() failure")                              \
    case kBudErrProxyline:                                                    \
      BUD_ERROR("Invalid proxyline value: %s", err.str)                       \
    case kBudErrInvalidUser:                                                  \
      BUD_ERROR("Invalid user name supplied: %s", err.str)                    \
    case kBudErrInvalidGroup:                                                 \
      BUD_ERROR("Invalid group name supplied: %s", err.str)                   \
    case kBudErrSetuid:                                                       \
      BUD_ERROR("setuid() failed: %d", err.ret)                               \
    case kBudErrSetgid:                                                       \
      BUD_ERROR("setgid() failed: %d", err.ret)                               \
    case kBudErrLoadDH:                                                       \
      BUD_ERROR("Failed to load DH params from %s, reason: %s",               \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrParseDH:                                                      \
      BUD_ERROR("Failed to load/parse DH params from %s reason: %s",          \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrInvalidBalance:                                               \
      BUD_ERROR("Invalid balance, should be `round-robin` or `on-fail`, "     \
                    "not `%s`",                                               \
                err.str)                                                      \
    case kBudErrDLOpen:                                                       \
      BUD_UV_ERROR("uv_dlopen(file)", err)                                    \
    case kBudErrDLSym:                                                        \
      BUD_UV_ERROR("uv_dlsym(file, symbol)", err)                             \
    case kBudErrForkFailed:                                                   \
      BUD_ERROR("fork() failed, errno: %d\n", err.ret)                        \
    case kBudErrSetsidFailed:                                                 \
      BUD_ERROR("setsid() failed, errno: %d\n", err.ret)                      \
    case kBudErrChdirFailed:                                                  \
      BUD_ERROR("chdir() failed, errno: %d\n", err.ret)                       \
    case kBudErrIPCPipeInit:                                                  \
      BUD_UV_ERROR("uv_pipe_init(ipc)", err)                                  \
    case kBudErrIPCPipeOpen:                                                  \
      BUD_UV_ERROR("uv_pipe_open(ipc)", err)                                  \
    case kBudErrIPCReadStart:                                                 \
      BUD_UV_ERROR("uv_read_start(ipc)", err)                                 \
    case kBudErrRestartTimer:                                                 \
      BUD_UV_ERROR("uv_timer_init(restart_timer)", err)                       \
    case kBudErrSpawn:                                                        \
      BUD_UV_ERROR("uv_spawn(worker)", err)                                   \
    case kBudErrSignalInit:                                                   \
      BUD_UV_ERROR("uv_signal_init()", err)                                   \
    case kBudErrSignalStart:                                                  \
      BUD_UV_ERROR("uv_signal_start()", err)                                  \
    case kBudErrTcpServerInit:                                                \
      BUD_UV_ERROR("uv_tcp_init(server)", err)                                \
    case kBudErrPton:                                                         \
      BUD_UV_ERROR("uv_inet_pton()", err)                                     \
    case kBudErrNtop:                                                         \
      BUD_UV_ERROR("uv_inet_ntop()", err)                                     \
    case kBudErrTcpServerBind:                                                \
      BUD_UV_ERROR("uv_tcp_bind(server)", err)                                \
    case kBudErrServerListen:                                                 \
      BUD_UV_ERROR("uv_listen(server)", err)                                  \
    case kBudErrServerIPCAccept:                                              \
      BUD_UV_ERROR("uv_accept(ipc)", err)                                     \
    case kBudErrServerSimAccept:                                              \
      BUD_UV_ERROR("uv_tcp_simultaneous_accepts(server, 0)", err)             \
    case kBudErrParserNeedMore:                                               \
      BUD_ERROR("client hello parser needs more data")                        \
    case kBudErrParserErr:                                                    \
      BUD_ERROR("client hello parser failure: %s", err.str)                   \
    case kBudErrHttpTcpInit:                                                  \
      BUD_UV_ERROR("uv_tcp_init(http_req)", err)                              \
    case kBudErrHttpTcpConnect:                                               \
      BUD_UV_ERROR("uv_tcp_connect(http_req)", err)                           \
    case kBudErrHttpWrite:                                                    \
      BUD_UV_ERROR("uv_write(http_req)", err)                                 \
    case kBudErrHttpWriteCb:                                                  \
      BUD_UV_ERROR("http_req's write_cb", err)                                \
    case kBudErrHttpConnectCb:                                                \
      BUD_UV_ERROR("http_req's connect_cb", err)                              \
    case kBudErrHttpReadStart:                                                \
      BUD_UV_ERROR("uv_read_start(http_req)", err)                            \
    case kBudErrHttpReadCb:                                                   \
      BUD_UV_ERROR("http_req's read_cb", err)                                 \
    case kBudErrHttpParse:                                                    \
      BUD_ERROR("http_req's body parse failed %s", err.str)                   \
    case kBudErrHttpEof:                                                      \
      BUD_ERROR("http_req's unexpected eof")                                  \
    case kBudErrStaplingSetData:                                              \
      BUD_ERROR("SSL_set_ex_data(stapling ctx) failed")                       \
    case kBudErrMaxRetries:                                                   \
      BUD_ERROR("Tried hard, but failed to reconnect")                        \
    case kBudErrRetryTimerStart:                                              \
      BUD_UV_ERROR("uv_read_start(retry_timer)", err)                         \
    case kBudErrRetryAfterClose:                                              \
      BUD_ERROR("Closed, can\'t retry")                                       \
    case kBudErrClientReadStart:                                              \
      BUD_UV_ERROR("uv_read_start(client)", err)                              \
    case kBudErrClientReadStop:                                               \
      BUD_UV_ERROR("uv_read_stop(client)", err)                               \
    case kBudErrClientWrite:                                                  \
      BUD_UV_ERROR("uv_write(client)", err)                                   \
    case kBudErrClientWriteCb:                                                \
      BUD_UV_ERROR("uv_write(client) cb", err)                                \
    case kBudErrClientTryWrite:                                               \
      BUD_UV_ERROR("uv_try_write(client)", err)                               \
    case kBudErrClientConnect:                                                \
      BUD_UV_ERROR("uv_connect(client)", err)                                 \
    case kBudErrClientReadCb:                                                 \
      BUD_UV_ERROR("uv_read_start(client) cb", err)                           \
    case kBudErrClientWriteAppend:                                            \
      BUD_ERROR("ringbuffer_write_append(client)")                            \
    case kBudErrClientSetExData:                                              \
      BUD_ERROR("SSL_set_ex_data() for SNI")                                  \
    case kBudErrClientSSLWrite:                                               \
      BUD_ERROR("SSL_write(client) - %d (%s)",                                \
                err.ret,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrClientSSLRead:                                                \
      BUD_ERROR("SSL_read(client) - %d (%s)",                                 \
                err.ret,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrClientThrottle:                                               \
      BUD_ERROR("throttle(client) **NOT A ERROR**")                           \
    case kBudErrClientShutdown:                                               \
      BUD_UV_ERROR("uv_shutdown(client)", err)                                \
    case kBudErrClientShutdownCb:                                             \
      BUD_UV_ERROR("uv_shutdown(client) cb", err)                             \
    case kBudErrClientRenegotiationAttack:                                    \
      BUD_ERROR("Renegotiation attack prevented")                             \
    case kBudErrClientRetry:                                                  \
      BUD_ERROR("retry connecting to backend")                                \
    case kBudErrClientProxyline:                                              \
      BUD_ERROR("append proxyline")                                           \
    case kBudErrClientNoBackendInSNI:                                         \
      BUD_ERROR("no backend provided in SNI context")                         \
    case kBudErrClientXForwardInsert:                                         \
      BUD_ERROR("failed to prepend x-forwarded-for header")                   \
    default:                                                                  \
      UNEXPECTED;                                                             \
  }

#define BUD_ERROR(...)                                                        \
    bud_log(config, level, __VA_ARGS__);                                      \
    break;

#define BUD_UV_ERROR(msg, err)                                                \
    bud_log(config,                                                           \
            level,                                                            \
            msg " returned %d, reason: %s",                                   \
            err.ret,                                                          \
            uv_strerror(err.ret));                                            \
    break;

void bud_error_log(bud_config_t* config,
                   int level,
                   bud_error_t err) {
  BUD_ERROR_HANDLER(err)
}

#undef BUD_ERROR
#undef BUD_UV_ERROR

#define BUD_ERROR(...)                                                        \
    fprintf(fp, __VA_ARGS__);                                                 \
    fprintf(fp, "\n");                                                        \
    break;

#define BUD_UV_ERROR(msg, err)                                                \
    fprintf(fp, msg " returned %d\n", err.ret);                               \
    fprintf(fp, "%s\n", uv_strerror(err.ret));                                \
    break;

void bud_error_print(FILE* fp, bud_error_t err) {
  BUD_ERROR_HANDLER(err)
}

#undef BUD_ERROR
#undef BUD_UV_ERROR

#define BUD_ERROR(...)                                                        \
    snprintf(storage, sizeof(storage), __VA_ARGS__);                          \
    break;

#define BUD_UV_ERROR(msg, err)                                                \
    snprintf(storage,                                                         \
             sizeof(storage),                                                 \
             msg " returned %d (%s)",                                         \
             err.ret,                                                         \
             uv_strerror(err.ret));                                           \
    break;


const char* bud_error_to_str(bud_error_t err) {
  static char storage[1024];

  BUD_ERROR_HANDLER(err)

  return storage;
}

#undef BUD_ERROR
#undef BUD_UV_ERROR
