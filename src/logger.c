#include <stdlib.h>  /* calloc, free */
#include <unistd.h>  /* getpid */

#include "error.h"
#include "common.h"
#include "config.h"
#include "logger.h"

static const char* bud_log_level_str(bud_log_level_t level);


bud_error_t bud_logger_new(bud_config_t* config) {
  config->logger = calloc(1, sizeof(*config->logger));
  config->logger->level = kBudLogInfo;
  return bud_ok();
}


void bud_logger_free(bud_config_t* config) {
  if (config->logger == NULL)
    return;

  free(config->logger);
  config->logger = NULL;
}


void bud_log(bud_config_t* config, bud_log_level_t level, char* fmt, ...) {
  bud_logger_t* logger;
  int r;
  static char buf[1024];
  va_list ap;

  logger = config->logger;
  ASSERT(logger != NULL, "Logger not initalized");

  /* Ignore low-level logging */
  if (logger->level > level)
    return;

  va_start(ap, fmt);
  r = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  ASSERT(r < (int) sizeof(buf), "Log line overflow");

  fprintf(stderr,
          "(%s) [%d] %s\n",
          bud_log_level_str(level),
#ifndef _WIN32
          getpid(),
#else
          0,
#endif  /* !_WIN32 */
          buf);
}


const char* bud_log_level_str(bud_log_level_t level) {
  switch (level) {
    case kBudLogDebug:
      return "dbg";
    case kBudLogInfo:
      return "inf";
    case kBudLogWarning:
      return "wrn";
    case kBudLogFatal:
      return "ftl";
  }
}
