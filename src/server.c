#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>  /* calloc, free */
#include <string.h>  /* snprintf */

#include "uv.h"

#include "master.h"
#include "server.h"
#include "client.h"

static void bud_server_close_cb(uv_handle_t* handle);
static void bud_server_connection_cb(uv_stream_t* stream, int status);
static bud_error_t bud_server_format_proxyline(bud_server_t* server);

bud_error_t bud_server_new(bud_config_t* config) {
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

  r = uv_tcp_bind(&server->tcp, (struct sockaddr*) &config->frontend.addr);
  if (r != 0) {
    err = bud_error_num(kBudErrTcpServerBind, r);
    goto failed_bind;
  }

  r = uv_listen((uv_stream_t*) &server->tcp, 256, bud_server_connection_cb);
  if (r != 0) {
    err = bud_error_num(kBudErrServerListen, r);
    goto failed_bind;
  }

  if (config->frontend.proxyline)
    err = bud_server_format_proxyline(server);
  else
    err = bud_ok();

  config->server = server;
  return err;

failed_bind:
  uv_close((uv_handle_t*) &server->tcp, bud_server_close_cb);
  return err;

failed_tcp_init:
  free(server);

  return err;
}


void bud_server_free(bud_config_t* config) {
  config->server->config = NULL;
  uv_close((uv_handle_t*) &config->server->tcp, bud_server_close_cb);
  config->server = NULL;
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


bud_error_t bud_server_format_proxyline(bud_server_t* server) {
  int r;
  char host[INET6_ADDRSTRLEN];
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;
  bud_config_t* config;

  config = server->config;
  addr4 = (struct sockaddr_in*) &config->frontend.addr;
  addr6 = (struct sockaddr_in6*) &config->frontend.addr;

  if (config->frontend.addr.ss_family == AF_INET)
    r = uv_inet_ntop(AF_INET, &addr4->sin_addr, host, sizeof(host));
  else
    r = uv_inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
  if (r != 0)
    return bud_error(kBudErrNtop);

  r = snprintf(config->proxyline_fmt,
               sizeof(config->proxyline_fmt),
               "PROXY %%s %%s %s %%hu %hu\r\n",
               host,
               config->frontend.port);
  ASSERT(r < (int) sizeof(config->proxyline_fmt),
         "Proxyline format overflowed");

  return bud_ok();
}
