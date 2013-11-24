#include <stdlib.h>  /* calloc, free */
#include <string.h>  /* strcmp */
#ifndef _WIN32
#include <syslog.h>
#endif  /* !_WIN32 */
#include <unistd.h>  /* getpid */

#include "error.h"
#include "common.h"
#include "config.h"
#include "logger.h"

static const char* bud_log_level_str(bud_log_level_t level);


bud_error_t bud_logger_new(bud_config_t* config) {
  config->logger = calloc(1, sizeof(*config->logger));
  if (strcmp(config->log_level, "debug") == 0)
    config->logger->level = kBudLogDebug;
  else if (strcmp(config->log_level, "notice") == 0)
    config->logger->level = kBudLogNotice;
  else if (strcmp(config->log_level, "fatal") == 0)
    config->logger->level = kBudLogFatal;
  else if (strcmp(config->log_level, "warning") == 0)
    config->logger->level = kBudLogWarning;
  else
    config->logger->level = kBudLogInfo;
  config->logger->stdio_enabled = config->log_stdio;
  config->logger->syslog_enabled = config->log_syslog;
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
#ifndef _WIN32
  int priority;
#endif  /* !_WIN32 */

  logger = config->logger;
  ASSERT(logger != NULL, "Logger not initalized");

  /* Ignore low-level logging */
  if (logger->level > level)
    return;

  va_start(ap, fmt);
  if (logger->stdio_enabled) {
    r = vsnprintf(buf, sizeof(buf), fmt, ap);
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

#ifndef _WIN32
  if (logger->syslog_enabled) {
    switch (level) {
      case kBudLogDebug:
        priority = LOG_DEBUG;
        break;
      case kBudLogNotice:
        priority = LOG_NOTICE;
        break;
      case kBudLogInfo:
        priority = LOG_INFO;
        break;
      case kBudLogFatal:
        priority = LOG_ERR;
        break;
      case kBudLogWarning:
      default:
        priority = LOG_WARNING;
        break;
    }
    vsyslog(priority, fmt, ap);
  }
#endif  /* !_WIN32 */
  va_end(ap);
}


const char* bud_log_level_str(bud_log_level_t level) {
  switch (level) {
    case kBudLogDebug:
      return "dbg";
    case kBudLogNotice:
      return "ntc";
    case kBudLogInfo:
      return "inf";
    case kBudLogWarning:
      return "wrn";
    case kBudLogFatal:
      return "ftl";
    default:
      return "unk";
  }
}
