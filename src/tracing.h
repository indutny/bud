#ifndef SRC_TRACING_H_
#define SRC_TRACING_H_

/* Forward declarations */
struct bud_client_s;

void bud_trace_frontend_accept(struct bud_client_s* client);
void bud_trace_backend_connect(struct bud_client_s* client);
void bud_trace_end(struct bud_client_s* client);
void bud_trace_handshake(struct bud_client_s* client);

#endif  /* SRC_TRACING_H_ */
