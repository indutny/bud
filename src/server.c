#include <arpa/inet.h>  /* ntohs */
#include <stdlib.h>  /* calloc, free */
#include <string.h>  /* snprintf */

#include "uv.h"

#include "server.h"
#include "client.h"

static void bud_server_close_cb(uv_handle_t* handle);
static void bud_server_connection_cb(uv_stream_t* stream, int status);
static bud_error_t bud_server_format_proxyline(bud_server_t* server);
static int bud_server_str_to_addr(const char* host,
                                  uint16_t port,
                                  struct sockaddr_storage* addr);

bud_server_t* bud_server_new(uv_loop_t* loop,
                             bud_config_t* config,
                             bud_error_t* err) {
  int r;
  bud_server_t* server;

  server = calloc(1, sizeof(*server));

  server->config = config;
  r = uv_tcp_init(loop, &server->tcp);
  if (r != 0) {
    *err = bud_error_num(kBudErrTcpServerInit, r);
    goto failed_tcp_init;
  }

  r = bud_server_str_to_addr(config->frontend.host,
                             config->frontend.port,
                             &server->frontend);
  if (r != 0) {
    *err = bud_error_num(kBudErrIpv4Addr, r);
    goto failed_ipv4_addr;
  }

  r = bud_server_str_to_addr(config->backend.host,
                             config->backend.port,
                             &server->backend);
  if (r != 0) {
    *err = bud_error_num(kBudErrIpv4Addr, r);
    goto failed_ipv4_addr;
  }

  r = uv_tcp_bind(&server->tcp, (struct sockaddr*) &server->frontend);
  if (r != 0) {
    *err = bud_error_num(kBudErrTcpServerBind, r);
    goto failed_ipv4_addr;
  }

  r = uv_listen((uv_stream_t*) &server->tcp, 256, bud_server_connection_cb);
  if (r != 0) {
    *err = bud_error_num(kBudErrServerListen, r);
    goto failed_ipv4_addr;
  }

  if (config->frontend.proxyline)
    *err = bud_server_format_proxyline(server);
  else
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


void bud_server_connection_cb(uv_stream_t* stream, int status) {
  bud_server_t* server;

  server = container_of(stream, bud_server_t, tcp);

  /* Create client and let it go */
  bud_client_create(server);
}


bud_error_t bud_server_format_proxyline(bud_server_t* server) {
  int r;
  char host[INET6_ADDRSTRLEN];
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;

  addr4 = (struct sockaddr_in*) &server->frontend;
  addr6 = (struct sockaddr_in6*) &server->backend;

  if (server->frontend.ss_family == AF_INET)
    r = uv_inet_ntop(AF_INET, &addr4->sin_addr, host, sizeof(host));
  else
    r = uv_inet_ntop(AF_INET6, &addr6->sin6_addr, host, sizeof(host));
  if (r != 0)
    return bud_error(kBudErrIpv4Name);

  r = snprintf(server->proxyline_fmt,
               sizeof(server->proxyline_fmt),
               "PROXY %%s %%s %s %%hu %hu\r\n",
               host,
               server->config->frontend.port);
  ASSERT(r < (int) sizeof(server->proxyline_fmt),
         "Proxyline format overflowed");

  return bud_ok();
}


int bud_server_str_to_addr(const char* host,
                           uint16_t port,
                           struct sockaddr_storage* addr) {
  int r;
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;

  addr4 = (struct sockaddr_in*) addr;
  addr6 = (struct sockaddr_in6*) addr;

  r = uv_inet_pton(AF_INET, host, &addr4->sin_addr);
  if (r == 0) {
    addr4->sin_family = AF_INET;
    addr4->sin_len = sizeof(*addr4);
    addr4->sin_port = htons(port);
  } else {
    addr6->sin6_family = AF_INET6;
    addr6->sin6_len = sizeof(*addr6);
    r = uv_inet_pton(AF_INET6, host, &addr6->sin6_addr);
    if (r == 0)
      addr6->sin6_port = htons(port);
  }

  return r;
}
