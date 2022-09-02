#ifndef _FIDO_SGX_CA_H_
#define _FIDO_SGX_CA_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "fido_sgx_sod_dg.h"


BUF_MEM *
CA_STEP1_get_epass_pubkey(const EPASS_CTX *epass_ctx);

BUF_MEM *
CA_STEP2_generate_eph_keypair(const EPASS_CTX *epass_ctx);

int
CA_STEP4_compute_shared_secret(const EPASS_CTX *epass_ctx, const BUF_MEM *pubkey);

BUF_MEM *
CA_get_pubkey(const EPASS_CTX *epass_ctx,
        const unsigned char *ef_cardsecurity,
        size_t ef_cardsecurity_len);

int
CA_set_key(const EPASS_CTX *epass_ctx,
        const unsigned char *priv, size_t priv_len,
        const unsigned char *pub, size_t pub_len);
int
CA_STEP6_derive_keys(const EPASS_CTX *epass_ctx);

#if defined(__cplusplus)
}
#endif

#endif /* !_FIDO_SGX_CA_H_ */
