#include <getopt.h>  /* getopt */
#include <stdio.h>  /* fprintf */
#include <stdlib.h>  /* NULL */

#include "parson.h"

#include "config.h"
#include "common.h"
#include "version.h"

static int bud_config_init(bud_config_t* config);
static void bud_config_set_defaults(bud_config_t* config);
static void bud_print_help(int argc, char** argv);
static void bud_print_version();
static void bud_config_print_default();


bud_config_t* bud_config_cli_load(int argc, char** argv) {
  int index;
  int ch;
  struct option long_options[] = {
    { "version", 0, NULL, 0 },
    { "config", 1, NULL, 0 },
    { "default-config", 0, NULL, 1 },
    { NULL, 0, NULL, 0 }
  };

  while ((ch = getopt_long(argc, argv, "vc:", long_options, &index)) != -1) {
    /* Print version number */
    if (ch == 'v' || index == 0) {
      bud_print_version();
      return NULL;
    }

    /* Load configuration from file */
    if (ch == 'c' || index == 1)
      return bud_config_load(optarg);

    if (index == 2) {
      bud_config_print_default();
      return NULL;
    }
  }

  bud_print_help(argc, argv);
  return NULL;
}


bud_config_t* bud_config_load(const char* path) {
  JSON_Value* json;
  JSON_Object* obj;
  bud_config_t* config;

  json = json_parse_file(path);
  if (json == NULL) {
    fprintf(stderr, "Failed to load or parse: %s\n", path);
    goto end;
  }

  obj = json_value_get_object(json);
  if (obj == NULL) {
    fprintf(stderr, "Invalid json, root should be an object\n");
    goto failed_get_object;
  }

  config = calloc(1, sizeof(*config));
  ASSERT(config != NULL, "Failed to allocate config");

  config->port = (uint16_t) json_object_get_number(obj, "port");
  config->host = json_object_get_string(obj, "host");
  config->cert_file = json_object_get_string(obj, "cert");
  config->key_file = json_object_get_string(obj, "key");
  config->ca_file = json_object_get_string(obj, "ca");

  bud_config_set_defaults(config);
  if (bud_config_init(config) != 0) {
    bud_config_free(config);
    return NULL;
  }

  return config;

failed_get_object:
  json_value_free(json);

end:
  return NULL;
}


void bud_config_free(bud_config_t* config) {
  json_value_free(config->json);
  config->json = NULL;
  free(config);
}


void bud_print_help(int argc, char** argv) {
  ASSERT(argc >= 1, "Not enough arguments");
  fprintf(stdout, "Usage: %s [options]\n\n", argv[0]);
  fprintf(stdout, "options:\n");
  fprintf(stdout, "  --version, -v              Print bud version\n");
  fprintf(stdout, "  --config PATH, -c PATH     Load JSON configuration\n");
  fprintf(stdout, "  --default-config           Print default JSON config\n");
  fprintf(stdout, "\n");
}


void bud_print_version() {
  fprintf(stdout, "bud %d.%d\n", BUD_VERSION_MAJOR, BUD_VERSION_MINOR);
}


void bud_config_print_default() {
  bud_config_t config;

  bud_config_set_defaults(&config);

  fprintf(stdout, "{\n");
  fprintf(stdout, "  \"port\": %d,\n", config.port);
  fprintf(stdout, "  \"host\": \"%s\",\n", config.host);
  fprintf(stdout, "  \"cert\": \"%s\",\n", config.cert_file);
  fprintf(stdout, "  \"key\": \"%s\",\n", config.key_file);
  if (config.ca_file != NULL)
    fprintf(stdout, "  \"ca\": \"%s\"\n", config.ca_file);
  else
    fprintf(stdout, "  \"ca\": null\n");
  fprintf(stdout, "}\n");
}


int bud_config_init(bud_config_t* config) {
  return 0;
}


#define DEFAULT(param, null, value)                                           \
    do {                                                                      \
      if ((param) == (null))                                                  \
        (param) = (value);                                                    \
    } while (0)

void bud_config_set_defaults(bud_config_t* config) {
  DEFAULT(config->port, 0, 1443);
  DEFAULT(config->host, NULL, "0.0.0.0");
  DEFAULT(config->cert_file, NULL, "cert.pem");
  DEFAULT(config->key_file, NULL, "key.pem");
}

#undef DEFAULT
