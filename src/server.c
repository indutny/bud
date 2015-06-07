#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>  /* calloc, free */
#include <string.h>  /* snprintf */

#include "uv.h"

#include "src/master.h"
#include "src/server.h"
#include "src/client.h"

static bud_error_t bud_server_new(bud_config_t* config,
                                  bud_config_addr_t* addr);
static void bud_server_free(bud_server_t* server);
static void bud_server_close_cb(uv_handle_t* handle);
static void bud_server_connection_cb(uv_stream_t* stream, int status);

bud_error_t bud_create_servers(bud_config_t* config) {
  bud_error_t err;
  int i;

  if (config->frontend.interface.count == 0) {
    err = bud_server_new(config, (bud_config_addr_t*) &config->frontend);
    if (!bud_is_ok(err))
      goto fatal;
  }

  for (i = 0; i < config->frontend.interface.count; i++) {
    err = bud_server_new(config, &config->frontend.interface.list[i]);
    if (!bud_is_ok(err))
      goto fatal;
  }
  return bud_ok();

fatal:
  bud_free_servers(config);
  return err;
}


bud_error_t bud_server_new(bud_config_t* config, bud_config_addr_t* addr) {
  int r;
  bud_error_t err;
  bud_server_t* server;

  server = calloc(1, sizeof(*server));

  server->config = config;

  /* Initialize tcp handle */
  r = uv_tcp_init(config->loop, &server->tcp);
  if (r != 0) {
    err = bud_error_num(kBudErrTcpServerInit, r);
    goto failed_tcp_init;
  }

  r = uv_tcp_bind(&server->tcp, (struct sockaddr*) &addr->addr, 0);
  if (r != 0) {
    err = bud_error_num(kBudErrTcpServerBind, r);
    goto failed_bind;
  }

  r = uv_listen((uv_stream_t*) &server->tcp, 256, bud_server_connection_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrServerListen, r);
    goto failed_bind;
  }

  server->prev = config->server;
  config->server = server;
  return bud_ok();

failed_bind:
  uv_close((uv_handle_t*) &server->tcp, bud_server_close_cb);
  return err;

failed_tcp_init:
  free(server);

  return err;
}


void bud_free_servers(bud_config_t* config) {
  bud_server_t* server;

  server = config->server;
  while (server != NULL) {
    bud_server_t* prev;

    prev = server->prev;
    bud_server_free(server);
    server = prev;
  }

  config->server = NULL;
}


void bud_server_free(bud_server_t* server) {
  server->config = NULL;
  uv_close((uv_handle_t*) &server->tcp, bud_server_close_cb);
}


void bud_server_close_cb(uv_handle_t* handle) {
  bud_server_t* server;

  server = container_of(handle, bud_server_t, tcp);
  free(server);
}


void bud_server_connection_cb(uv_stream_t* stream, int status) {
  bud_server_t* server;

  server = container_of(stream, bud_server_t, tcp);

  /* Create client and let it go */
  bud_master_balance(server);
}
