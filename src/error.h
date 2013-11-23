#ifndef SRC_ERROR_H_
#define SRC_ERROR_H_

#include <stdio.h>

typedef enum bud_error_code_e bud_error_code_t;
typedef struct bud_error_s bud_error_t;

enum bud_error_code_e {
  kBudOk = 0,

  /* General errors */
  kBudErrNoMem = 0x001,
  kBudErrForkFailed = 0x002,
  kBudErrSetsidFailed = 0x003,
  kBudErrChdirFailed = 0x004,

  /* Config errors */
  kBudErrJSONParse = 0x100,
  kBudErrJSONNonObjectRoot = 0x101,
  kBudErrJSONNonObjectCtx = 0x102,
  kBudErrParseCert = 0x103,
  kBudErrParseKey = 0x104,
  kBudErrSNINotSupported = 0x105,
  kBudErrNPNNonString = 0x106,
  kBudErrNPNNotSupported = 0x107,

  /* Server errors */
  kBudErrTcpServerInit = 0x200,
  kBudErrIpv4Addr = 0x201,
  kBudErrIpv4Name = 0x202,
  kBudErrTcpServerBind = 0x203,
  kBudErrServerListen = 0x204
};

struct bud_error_s {
  bud_error_code_t code;
  const char* str;
  int ret;
};

bud_error_t bud_ok();
int bud_is_ok(bud_error_t err);
bud_error_t bud_error(bud_error_code_t code);
bud_error_t bud_error_str(bud_error_code_t code, const char* str);
bud_error_t bud_error_num(bud_error_code_t code, int ret);
void bud_error_print(FILE* fp, bud_error_t err);

#endif  /* SRC_ERROR_H_ */
