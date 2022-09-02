#include "fido_sgx_ca.h"

#include "openpace/eac_lib.h"
#include "openpace/eac_util.h"
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <openssl/err.h> // ERR_clear_error()

#include <openssl/x509.h>
#include <string.h>

#include "openpace/misc.h" // EAC_add_all_objects()


BUF_MEM *
CA_STEP1_get_epass_pubkey(const EPASS_CTX *epass_ctx)
{
    if(!(epass_ctx && epass_ctx->ca_ctx && epass_ctx->ca_ctx->ka_ctx)) {
        printf("Invalid arguments\n");
        return NULL;
    }

    if (!epass_ctx->ca_ctx->ka_ctx->peer_pubkey) {
        printf("KA context exists, but peer_pubkey is still NULL atm\n");
        return NULL;
    }

    // BN_CTX optional anyway?
    return get_pubkey(epass_ctx->ca_ctx->ka_ctx->peer_pubkey, NULL);
}

BUF_MEM *
CA_STEP2_generate_eph_keypair(const EPASS_CTX *epass_ctx)
{
    BUF_MEM *comp_pub_key, *pub_key = NULL;

    if(!epass_ctx || !epass_ctx->ca_ctx || !epass_ctx->ca_ctx->ka_ctx) {
        printf("Invalid arguments\n");
        return NULL;
    }

    // BN_CTX optional, right?
    // generate key pair? (DH/ECDH)
    // TODO: is the key pair somewhere perma-stored?
    pub_key = KA_CTX_generate_key(epass_ctx->ca_ctx->ka_ctx, NULL);

    if(!pub_key) {
        printf("Failed generating eph key pair\n");
        return NULL;
    }

#if 0
    // compress/encode public key
    comp_pub_key = Comp(epass_ctx->ca_ctx->ka_ctx->key, pub_key, NULL,
            NULL);

    if (pub_key)
        BUF_MEM_free(pub_key); // TODO: fine?

    return comp_pub_key;
#endif
    return pub_key;
}


int
CA_STEP4_compute_shared_secret(const EPASS_CTX *epass_ctx, const BUF_MEM *pubkey)
{
    // BN_CTX optional anyway?
    if (!epass_ctx || !epass_ctx->ca_ctx
            || !KA_CTX_compute_key(epass_ctx->ca_ctx->ka_ctx, pubkey, NULL)) {
        printf("Invalid arguments\n");
        return 0;
    }

    return 1;
}


#if 0
BUF_MEM *
CA_get_pubkey(const EPASS_CTX *epass_ctx,
        const unsigned char *ef_cardsecurity,
        size_t ef_cardsecurity_len)
{
    BUF_MEM *pubkey = NULL;
    EAC_CTX *signed_ctx = EAC_CTX_new();
    if(!epass_ctx || !epass_ctx->ca_ctx) {
        printf("Invalid arguments\n");
        goto err;
    }

#if 0
    if (ctx->ca_ctx->flags & CA_FLAG_DISABLE_PASSIVE_AUTH)
        CA_disable_passive_authentication(signed_ctx);
#endif

    if(!(EAC_CTX_init_ef_cardsecurity(ef_cardsecurity, ef_cardsecurity_len,
                signed_ctx)
            && signed_ctx && signed_ctx->ca_ctx && signed_ctx->ca_ctx->ka_ctx)) {
        printf("Could not parse EF.CardSecurity\n");
        goto err;
    }

    pubkey = get_pubkey(signed_ctx->ca_ctx->ka_ctx->key, signed_ctx->bn_ctx);

err:
    EAC_CTX_clear_free(signed_ctx);

    return pubkey;
}
#endif

int
CA_set_key(const EPASS_CTX *epass_ctx,
        const unsigned char *priv, size_t priv_len,
        const unsigned char *pub, size_t pub_len)
{
    int r = 0;
    const unsigned char *p = priv;
    EVP_PKEY *key = NULL;

    if(!epass_ctx || !epass_ctx->ca_ctx || !epass_ctx->ca_ctx->ka_ctx) {
        printf("Invalid arguments\n");
        goto err;
    }

    /* always try d2i_AutoPrivateKey as priv may contain domain parameters */
    if (priv && d2i_AutoPrivateKey(&key, &p, priv_len)) {
        EVP_PKEY_free(epass_ctx->ca_ctx->ka_ctx->key);
        epass_ctx->ca_ctx->ka_ctx->key = key;
        if (pub) {
            // BN_CTX optional anyway?
            /* it's OK if import of public key fails */
            EVP_PKEY_set_keys(key, NULL, 0, pub, pub_len, NULL);
        }
    } else {
        /* wipe errors from d2i_AutoPrivateKey() */
        ERR_clear_error();
        // BN_CTX optional anyway?
        if(!EVP_PKEY_set_keys(epass_ctx->ca_ctx->ka_ctx->key, priv, priv_len, pub,
                    pub_len, NULL)) {
            printf("no valid keys given\n");
            goto err;
        }
    }
    r = 1;

err:
    return r;
}


int
CA_STEP6_derive_keys(const EPASS_CTX *epass_ctx)
{
    int rv = -1;

    if(!epass_ctx || !epass_ctx->ca_ctx) {
        printf("Invalid arguments\n");
        goto err;
    }

    if (!KA_CTX_derive_keys(epass_ctx->ca_ctx->ka_ctx, NULL, NULL))
        goto err;

    rv = 1;

#if 0
    /* PACE, TA and CA were successful. Update the trust anchor! */
    if (rv) {
        if (ctx->ta_ctx->new_trust_anchor) {
            CVC_CERT_free(ctx->ta_ctx->trust_anchor);
            ctx->ta_ctx->trust_anchor = ctx->ta_ctx->new_trust_anchor;
            ctx->ta_ctx->new_trust_anchor = NULL;
        }
    }
#endif

err:
    return rv;
}
