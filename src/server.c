#include "uv.h"

#include "server.h"

static void bud_server_close_cb(uv_handle_t* handle);
static void bud_server_connection_cb(uv_stream_t* server, int status);

bud_server_t* bud_server_new(uv_loop_t* loop,
                             bud_config_t* config,
                             bud_error_t* err) {
  int r;
  bud_server_t* server;
  struct sockaddr_in addr;

  server = calloc(1, sizeof(*server));

  server->config = config;
  r = uv_tcp_init(loop, &server->tcp);
  if (r != 0) {
    *err = bud_error_num(kBudErrTcpServerInit, r);
    goto failed_tcp_init;
  }

  /* TODO(indutny): Support ipv6 too */
  r = uv_ip4_addr(config->host, config->port, &addr);
  if (r != 0) {
    *err = bud_error_num(kBudErrIpv4Addr, r);
    goto failed_ipv4_addr;
  }

  r = uv_tcp_bind(&server->tcp, (struct sockaddr*) &addr);
  if (r != 0) {
    *err = bud_error_num(kBudErrTcpServerBind, r);
    goto failed_ipv4_addr;
  }

  r = uv_listen((uv_stream_t*) &server->tcp, 256, bud_server_connection_cb);
  if (r != 0) {
    *err = bud_error_num(kBudErrServerListen, r);
    goto failed_ipv4_addr;
  }

  *err = bud_ok();
  return server;

failed_ipv4_addr:
  uv_close((uv_handle_t*) &server->tcp, bud_server_close_cb);
  return NULL;

failed_tcp_init:
  free(server);

  return NULL;
}


void bud_server_destroy(bud_server_t* server) {
  bud_config_free(server->config);
  server->config = NULL;
  uv_close((uv_handle_t*) &server->tcp, bud_server_close_cb);
}


void bud_server_close_cb(uv_handle_t* handle) {
  bud_server_t* server;

  server = container_of(handle, bud_server_t, tcp);
  free(server);
}


void bud_server_connection_cb(uv_stream_t* server, int status) {
}
