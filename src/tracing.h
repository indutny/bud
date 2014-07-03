#ifndef SRC_TRACING_H_
#define SRC_TRACING_H_

#include "bud/tracing.h"  /* public dso API */

/* Forward declarations */
struct bud_client_s;

#define BUD_TRACE_DECL(V) void bud_trace_##V(struct bud_client_s* client);

BUD_TRACING_ENUM(BUD_TRACE_DECL)

#undef BUD_TRACE_DECL

#endif  /* SRC_TRACING_H_ */
