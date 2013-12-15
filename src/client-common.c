#include "uv.h"

#include "client.h"
#include "client-common.h"
#include "error.h"


const char* bud_side_str(bud_client_side_type_t side) {
  if (side == kBudFrontend)
    return "frontend";
  else
    return "backend";
}


bud_client_error_t bud_client_error(bud_error_t err, bud_client_side_t* side) {
  bud_client_error_t cerr;

  cerr.err = err;
  cerr.side = side;

  return cerr;
}


bud_client_error_t bud_client_ok(bud_client_side_t* side) {
  return bud_client_error(bud_ok(), side);
}


bud_client_error_t bud_client_read_start(bud_client_t* client,
                                         bud_client_side_t* side) {
  int r;

  r = uv_read_start((uv_stream_t*) &side->tcp,
                    bud_client_alloc_cb,
                    bud_client_read_cb);
  if (r == 0)
    return bud_client_ok(side);

  return bud_client_error(bud_error_num(kBudErrClientReadStart, r), side);
}
