#ifndef SRC_ERROR_H_
#define SRC_ERROR_H_

#include <stdio.h>

/* Forward declaration */
struct bud_config_s;

typedef enum bud_error_code_e bud_error_code_t;
typedef struct bud_error_s bud_error_t;

enum bud_error_code_e {
  kBudOk = 0,

  /* General errors */
  kBudErrNoMem = 0x001,

  /* Config errors */
  kBudErrJSONParse = 0x100,
  kBudErrJSONNonObjectRoot = 0x101,
  kBudErrJSONNonObjectCtx = 0x102,
  kBudErrParseCert = 0x103,
  kBudErrParseKey = 0x104,
  kBudErrSNINotSupported = 0x105,
  kBudErrNPNNonString = 0x106,
  kBudErrNPNNotSupported = 0x107,
  kBudErrExePath = 0x108,

  /* Master/Worker errors */
  kBudErrForkFailed = 0x200,
  kBudErrSetsidFailed = 0x201,
  kBudErrChdirFailed = 0x202,
  kBudErrIPCPipeInit = 0x203,
  kBudErrIPCPipeOpen = 0x204,
  kBudErrIPCReadStart = 0x205,
  kBudErrRestartTimer = 0x206,
  kBudErrSpawn = 0x207,

  /* Server errors */
  kBudErrTcpServerInit = 0x300,
  kBudErrPton = 0x301,
  kBudErrNtop = 0x302,
  kBudErrTcpServerBind = 0x303,
  kBudErrServerListen = 0x304,
  kBudErrServerIPCAccept = 0x305,
  kBudErrServerSimAccept = 0x306
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
void bud_error_log(struct bud_config_s* config,
                   int level,
                   bud_error_t err);
void bud_error_print(FILE* fp, bud_error_t err);

#endif  /* SRC_ERROR_H_ */