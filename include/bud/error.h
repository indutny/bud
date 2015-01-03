#ifndef INCLUDE_BUD_ERROR_H_
#define INCLUDE_BUD_ERROR_H_

#include <stdio.h>  /* FILE */
#include "bud/common.h"

/* Forward declaration */
struct bud_config_s;

typedef enum bud_error_code_e bud_error_code_t;
typedef struct bud_error_s bud_error_t;

enum bud_error_code_e {
  kBudOk = 0,

  /* General errors */
  kBudErrNoMem = 0x001,
  kBudErrSkip = 0x002,

  /* Config errors */
  kBudErrJSONParse = 0x100,
  kBudErrJSONNonObjectRoot = 0x101,
  kBudErrJSONNonObjectCtx = 0x102,
  kBudErrLoadCert = 0x103,
  kBudErrParseCert = 0x104,
  kBudErrLoadKey = 0x105,
  kBudErrParseKey = 0x106,
  kBudErrSNINotSupported = 0x107,
  kBudErrNonString = 0x108,
  kBudErrNPNNotSupported = 0x109,
  kBudErrExePath = 0x10a,
  kBudErrECDHNotFound = 0x10b,
  kBudErrNoBackend = 0x10c,
  kBudErrNoSSLIndex = 0x10d,
  kBudErrSmallTicketKey = 0x10e,
  kBudErrAddCert = 0x10f,
  kBudErrProxyline = 0x110,
  kBudErrInvalidUser = 0x111,
  kBudErrInvalidGroup = 0x112,
  kBudErrSetuid = 0x113,
  kBudErrSetgid = 0x114,
  kBudErrLoadDH = 0x115,
  kBudErrParseDH = 0x116,
  kBudErrInvalidBalance = 0x117,
  kBudErrDLOpen = 0x118,
  kBudErrDLSym = 0x119,
  kBudErrDLVersion = 0x11a,
  kBudErrMultipleConfigs = 0x11b,
  kBudErrLoadFile = 0x11c,
  kBudErrNoConfig = 0x11d,
  kBudErrFSRead = 0x11e,

  /* Master/Worker errors */
  kBudErrForkFailed = 0x200,
  kBudErrSetsidFailed = 0x201,
  kBudErrChdirFailed = 0x202,
  /* x203 - x205, previously used by IPC */
  kBudErrRestartTimer = 0x206,
  kBudErrSpawn = 0x207,
  kBudErrSignalInit = 0x208,
  kBudErrSignalStart = 0x209,

  /* Server errors */
  kBudErrTcpServerInit = 0x300,
  kBudErrPton = 0x301,
  kBudErrNtop = 0x302,
  kBudErrTcpServerBind = 0x303,
  kBudErrServerListen = 0x304,
  kBudErrServerIPCAccept = 0x305,
  kBudErrServerSimAccept = 0x306,

  /* Client hello parser errors */
  kBudErrParserNeedMore = 0x400,
  kBudErrParserErr = 0x401,

  /* HTTP pool */
  kBudErrHttpTcpInit = 0x500,
  kBudErrHttpTcpConnect = 0x501,
  kBudErrHttpWrite = 0x502,
  kBudErrHttpWriteCb = 0x503,
  kBudErrHttpConnectCb = 0x504,
  kBudErrHttpReadStart = 0x505,
  kBudErrHttpReadCb = 0x506,
  kBudErrHttpParse = 0x507,
  kBudErrHttpEof = 0x508,

  /* Stapling */
  kBudErrStaplingSetData = 0x600,

  /* Availability */
  kBudErrMaxRetries = 0x700,
  kBudErrRetryTimerStart = 0x701,
  kBudErrRetryAfterClose = 0x702,

  /* Client */
  kBudErrClientReadStart = 0x800,
  kBudErrClientReadStop = 0x801,
  kBudErrClientWrite = 0x802,
  kBudErrClientWriteCb = 0x803,
  kBudErrClientTryWrite = 0x804,
  kBudErrClientConnect = 0x805,
  kBudErrClientReadCb = 0x806,
  kBudErrClientWriteAppend = 0x807,
  kBudErrClientSetExData = 0x808,
  kBudErrClientSSLWrite = 0x809,
  kBudErrClientSSLRead = 0x80a,
  kBudErrClientThrottle = 0x80b,
  kBudErrClientShutdown = 0x80c,
  kBudErrClientShutdownCb = 0x80d,
  kBudErrClientRenegotiationAttack = 0x80e,
  kBudErrClientRetry = 0x80f,
  kBudErrClientProxyline = 0x810,
  kBudErrClientNoBackendInSNI = 0x811,
  kBudErrClientXForwardInsert = 0x812,
  kBudErrClientShutdownNoConn = 0x813,

  /* IPC */
  kBudErrIPCPipeInit = 0x900,
  kBudErrIPCPipeOpen = 0x901,
  kBudErrIPCReadStart = 0x902,
  kBudErrIPCBalanceInit = 0x903,
  kBudErrIPCBalanceAccept = 0x904,
  kBudErrIPCBalanceWrite = 0x905,
  kBudErrIPCSend = 0x906
};

struct bud_error_s {
  bud_error_code_t code;
  union {
    const char* str;
    int ret;
  } data;
};

#define bud_is_ok(err) ((err).code == kBudOk)

BUD_EXPORT bud_error_t bud_ok();
BUD_EXPORT bud_error_t bud_error(bud_error_code_t code);
BUD_EXPORT bud_error_t bud_error_str(bud_error_code_t code, const char* str);
BUD_EXPORT bud_error_t bud_error_dstr(bud_error_code_t code, const char* str);
BUD_EXPORT bud_error_t bud_error_num(bud_error_code_t code, int ret);
BUD_EXPORT void bud_error_log(struct bud_config_s* config,
                              int level,
                              bud_error_t err);
BUD_EXPORT void bud_error_print(FILE* fp, bud_error_t err);
BUD_EXPORT const char* bud_error_to_str(bud_error_t err);

#endif  /* SRC_ERROR_H_ */
