#include <stdlib.h>
#include <string.h>

#include "src/config/files.h"
#include "src/common.h"
#include "src/config.h"


bud_error_t bud_config_files_reduce_size(bud_hashmap_item_t* item, void* arg) {
  size_t* size;

  size = arg;
  (*size) += item->key_len + 1 + strlen((char*) item->value) + 1;

  return bud_ok();
}


bud_error_t bud_config_files_reduce_copy(bud_hashmap_item_t* item, void* arg) {
  char** res;
  int len;

  res = arg;

  /* Copy key */
  memcpy(*res, item->key, item->key_len);
  (*res) += item->key_len;
  (*res)[0] = '\0';
  (*res)++;

  len = strlen((char*) item->value);
  memcpy(*res, item->value, len + 1);
  (*res) += len + 1;

  return bud_ok();
}


bud_error_t bud_config_get_files(bud_config_t* config,
                                 const char** files,
                                 size_t* size) {
  char* res;
  char* pres;

  if (config->files.str != NULL)
    goto done;

  /* Calculate size */
  *size = 0;
  bud_hashmap_iterate(&config->files.hashmap,
                      bud_config_files_reduce_size,
                      size);

  res = malloc(*size);
  if (res == NULL)
    return bud_error_str(kBudErrNoMem, "config files list");

  /* Copy data in */
  pres = res;
  bud_hashmap_iterate(&config->files.hashmap,
                      bud_config_files_reduce_copy,
                      &pres);

  config->files.str = res;
  config->files.len = *size;

done:
  *files = config->files.str;
  *size = config->files.len;
  return bud_ok();
}


bud_error_t bud_config_set_files(bud_config_t* config,
                                 const char* files,
                                 size_t size) {
  bud_error_t err;
  const char* end;

  end = files + size;
  while (files < end) {
    char* key;
    int key_len;
    const char* value;

    key = strdup(files);
    if (key == NULL) {
      return bud_error_str(kBudErrNoMem, "Failed to dup key");
    }
    key_len = strlen(key);
    files += key_len + 1;
    ASSERT(files < end, "Config file cache key OOB");
    value = strdup(files);
    if (value == NULL) {
      free(key);
      return bud_error_str(kBudErrNoMem, "Failed to dup value");
    }
    files += strlen(value) + 1;
    ASSERT(files <= end, "Config file cache value OOB");

    err = bud_hashmap_insert(&config->files.hashmap,
                             key,
                             key_len,
                             (void*) value);
    if (!bud_is_ok(err))
      return err;
  }

  return bud_ok();
}


bud_error_t bud_config_files_reduce_reload(bud_hashmap_item_t* item,
                                           void* arg) {
  bud_error_t err;
  bud_config_t* config;
  char* content;

  config = arg;

  ASSERT(config->loop != NULL, "Loop should be present");
  err = bud_read_file_by_path(config->loop, item->key, &content);
  /*
   * Ignore file read errors, it might be a permission problem
   * after dropping the privileges
   */
  if (!bud_is_ok(err))
    return bud_ok();

  free(item->value);
  item->value = content;

  return bud_ok();
}


bud_error_t bud_config_reload_files(bud_config_t* config) {
  bud_error_t err;

  err = bud_hashmap_iterate(&config->files.hashmap,
                            bud_config_files_reduce_reload,
                            config);
  if (!bud_is_ok(err))
    return err;

  /* Reset files string */
  free(config->files.str);
  config->files.str = NULL;
  config->files.len = 0;
  return bud_ok();
}
