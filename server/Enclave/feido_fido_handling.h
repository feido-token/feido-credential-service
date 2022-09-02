#ifndef _FEIDO_FIDO_HANDLING_H_
#define _FEIDO_FIDO_HANDLING_H_

#include "feido_ctx.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* FEIDO_FIDO_DERIVE_KEYS */
bool FEIDO_FIDO_derive_fido_keys(FEIDO_FIDO_CTX *ctx);

/* FEIDO_FIDO_REGISTER -> FEIDO_DONE */
bool FEIDO_FIDO_register(FEIDO_CTX *ctx);
/* FEIDO_FIDO_LOGIN -> FEIDO_DONE */
bool FEIDO_FIDO_login(FEIDO_CTX *ctx);

#if defined(__cplusplus)
}
#endif

#endif /* !_FEIDO_FIDO_HANDLING_H_ */
