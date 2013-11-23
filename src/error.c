#include <stdio.h>
#include <stdlib.h>

#include "openssl/err.h"
#include "uv.h"

#include "error.h"
#include "common.h"

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


void bud_error_print(FILE* fp, bud_error_t err) {
  switch (err.code) {
    case kBudOk:
      fprintf(fp, "?! No error ?!\n");
      break;
    case kBudErrNoMem:
      fprintf(fp, "Allocation failed: %s\n", err.str);
      break;
    case kBudErrForkFailed:
      fprintf(fp, "fork() failed, errno: %d\n", err.ret);
      break;
    case kBudErrSetsidFailed:
      fprintf(fp, "setsid() failed, errno: %d\n", err.ret);
      break;
    case kBudErrJSONParse:
      fprintf(fp, "Failed to load or parse JSON: %s\n", err.str);
      break;
    case kBudErrJSONNonObjectRoot:
      fprintf(fp, "Invalid json, root should be an object\n");
      break;
    case kBudErrJSONNonObjectCtx:
      fprintf(fp, "Invalid json, each context should be an object\n");
      break;
    case kBudErrParseCert:
      fprintf(fp, "Failed to load/parse cert %s:\n", err.str);
      ERR_print_errors_fp(fp);
      break;
    case kBudErrParseKey:
      fprintf(fp, "Failed to load/parse key %s:\n", err.str);
      ERR_print_errors_fp(fp);
      break;
    case kBudErrSNINotSupported:
      fprintf(fp, "SNI not supported, but multiple contexts were given\n");
      break;
    case kBudErrNPNNonString:
      fprintf(fp, "\"npn\" array should contain only strings\n");
      break;
    case kBudErrNPNNotSupported:
      fprintf(fp, "NPN not supported, but present in config\n");
      break;
    case kBudErrTcpServerInit:
      fprintf(fp, "uv_tcp_init(server) returned %d\n", err.ret);
      fprintf(fp, "%s\n", uv_strerror(err.ret));
      break;
    case kBudErrIpv4Addr:
      fprintf(fp, "uv_ipv4_addr() returned %d\n", err.ret);
      fprintf(fp, "%s\n", uv_strerror(err.ret));
      break;
    case kBudErrIpv4Name:
      fprintf(fp, "uv_ipv4_name() returned %d\n", err.ret);
      fprintf(fp, "%s\n", uv_strerror(err.ret));
      break;
    case kBudErrTcpServerBind:
      fprintf(fp, "uv_tcp_bind(server) returned %d\n", err.ret);
      fprintf(fp, "%s\n", uv_strerror(err.ret));
      break;
    case kBudErrServerListen:
      fprintf(fp, "uv_listen(server) returned %d\n", err.ret);
      fprintf(fp, "%s\n", uv_strerror(err.ret));
      break;
    default:
      UNEXPECTED;
  }
}
