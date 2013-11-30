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
    case kBudErrParseCert:                                                    \
      BUD_ERROR("Failed to load/parse cert %s reason: %s",                    \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrParseKey:                                                     \
      BUD_ERROR("Failed to load/parse key %s reason: %s",                     \
                err.str,                                                      \
                ERR_reason_error_string(ERR_get_error()))                     \
    case kBudErrSNINotSupported:                                              \
      BUD_ERROR("SNI not supported, but multiple contexts were given")        \
    case kBudErrNPNNonString:                                                 \
      BUD_ERROR("\"npn\" array should contain only strings")                  \
    case kBudErrNPNNotSupported:                                              \
      BUD_ERROR("NPN not supported, but present in config")                   \
    case kBudErrExePath:                                                      \
      BUD_UV_ERROR("uv_exe_path()", err)                                      \
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
