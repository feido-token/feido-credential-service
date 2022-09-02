#ifndef _FEIDO_KDF_H_
#define _FEIDO_KDF_H_

#include <unistd.h>

#include "fido_sgx_sod_dg.h"

#include <openssl/evp.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct feido_derive_info {
    const char *service_name;
    FORM_DG1 *personal_data;
} KDF_INFO;

EVP_PKEY *feido_derive_ecc_key_pair(KDF_INFO kdf_info);

#if defined(__cplusplus)
}
#endif

#endif /* !_FEIDO_KDF_H_ */
