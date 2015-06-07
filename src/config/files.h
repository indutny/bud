#ifndef SRC_CONFIG_FILES_H_
#define SRC_CONFIG_FILES_H_

#include "config.h"
#include "common.h"

bud_error_t bud_config_files_reduce_size(bud_hashmap_item_t* item,
                                         void* arg);
bud_error_t bud_config_files_reduce_copy(bud_hashmap_item_t* item,
                                         void* arg);
bud_error_t bud_config_files_reduce_reload(bud_hashmap_item_t* item,
                                           void* arg);
bud_error_t bud_config_free_files(bud_hashmap_item_t* item,
                                  void* arg);

#endif  /* SRC_CONFIG_FILES_H_ */
