#ifndef _FEIDO_REVOCATION_H_
#define _FEIDO_REVOCATION_H_

#include "feido_ctx.h"

#include <openssl/ssl.h>

#if defined(__cplusplus)
extern "C" {
#endif

// TODO: move into server ctx (currently there is only a SSL_CTX)
typedef struct feido_revocation_db_ctx {
    const int feido_query_eid_db;
    
    //TODO: certificates/public keys
    const char *ip4_address;
    short port;

    // TODO: mutex?
    SSL_CTX *db_ssl_ctx;
} FEIDO_REVOKE_CTX;

extern FEIDO_REVOKE_CTX feido_revoke_ctx;

bool FEIDO_check_eid_revocation_status(FEIDO_CTX *ctx);

#if defined(__cplusplus)
}
#endif

#endif /* !_FEIDO_REVOCATION_H_ */
