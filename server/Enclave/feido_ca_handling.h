#ifndef _FEIDO_CA_HANDLING_H_
#define _FEIDO_CA_HANDLING_H_

#include "feido_ctx.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* FEIDO_WAIT_CA_INIT -> FEIDO_CA_DONE (/ERROR/SHUTDOWN) */
bool FEIDO_handle_dgs_and_ca_protocol(FEIDO_CTX *ctx);

#if defined(__cplusplus)
}
#endif

#endif /* !_FEIDO_CA_HANDLING_H_ */