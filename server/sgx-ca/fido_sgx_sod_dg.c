#include "fido_sgx_sod_dg.h"

#include <openssl/cms.h>

#include <eac/objects.h>

#include "sod_asn1.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>

#include <openssl/evp.h>
#include <string.h>

#include <openssl/safestack.h>

#include <openssl/x509.h>

#include "openpace/ca_lib.h"    // CA_CTX_set_protocol()
#include "openpace/eac_util.h"  // EVP_PKEY_set_keys()

#include "fido_sgx_ca_debug.h"

#ifdef FIDO_SGX_CA_GLOBAL_DEBUG
#define SOD_SG_DEBUG
#endif

// eac_asn1.c

/** Algorithm Identifier structure */
typedef struct algorithm_identifier_st {
    /** OID of the algorithm */
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} ALGORITHM_IDENTIFIER;

/** Subject Public Key Info structure */
typedef struct subject_public_key_info_st {
    ALGORITHM_IDENTIFIER *algorithmIdentifier;
    ASN1_BIT_STRING *subjectPublicKey;
} SUBJECT_PUBLIC_KEY_INFO;

/** ChipAuthenticationInfo structure */
typedef struct ca_info_st {
    /** OID */
    ASN1_OBJECT *protocol;
    /** Protocol Version number. Currently Version 1 and Version 2 are supported */
    ASN1_INTEGER *version;
    /** keyID MAY be used to indicate the local key identifier */
    ASN1_INTEGER *keyID;
} CA_INFO;

#if 0 // CAv2 (ePassport uses v1)
/** CA Domain parameter structure */
typedef struct ca_dp_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual domain parameters */
    ALGORITHM_IDENTIFIER *aid;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided */
    ASN1_INTEGER *keyID;
} CA_DP_INFO;
#endif

/** CA public key info */
typedef struct ca_public_key_info_st {
    /** OID of the type of domain parameters*/
    ASN1_OBJECT *protocol;
    /** The actual public key */
    SUBJECT_PUBLIC_KEY_INFO *chipAuthenticationPublicKeyInfo;
    /** Optional: specifies the local domain parameters if multiple sets of domain
        parameters are provided */
    ASN1_INTEGER *keyID;
} CA_PUBLIC_KEY_INFO;

ASN1_SEQUENCE(ALGORITHM_IDENTIFIER) = {
    ASN1_SIMPLE(ALGORITHM_IDENTIFIER, algorithm, ASN1_OBJECT),
    ASN1_OPT(ALGORITHM_IDENTIFIER, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(ALGORITHM_IDENTIFIER)

ASN1_SEQUENCE(SUBJECT_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(SUBJECT_PUBLIC_KEY_INFO, algorithmIdentifier, ALGORITHM_IDENTIFIER),
        ASN1_SIMPLE(SUBJECT_PUBLIC_KEY_INFO, subjectPublicKey, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SUBJECT_PUBLIC_KEY_INFO)

/* ChipAuthenticationInfo */
ASN1_SEQUENCE(CA_INFO) = {
    ASN1_SIMPLE(CA_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CA_INFO, version, ASN1_INTEGER),
    ASN1_OPT(CA_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_INFO)

#if 0 // CAv2 (ePassport uses v1)
/* ChipAuthenticationDomainParameterInfo */
ASN1_SEQUENCE(CA_DP_INFO) = {
    ASN1_SIMPLE(CA_DP_INFO, protocol, ASN1_OBJECT),
    ASN1_SIMPLE(CA_DP_INFO, aid, ALGORITHM_IDENTIFIER),
    ASN1_OPT(CA_DP_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_DP_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_DP_INFO)
#endif

/* ChipAuthenticationPublicKeyInfo */
ASN1_SEQUENCE(CA_PUBLIC_KEY_INFO) = {
        ASN1_SIMPLE(CA_PUBLIC_KEY_INFO, protocol, ASN1_OBJECT),
        ASN1_SIMPLE(CA_PUBLIC_KEY_INFO, chipAuthenticationPublicKeyInfo, SUBJECT_PUBLIC_KEY_INFO),
        ASN1_OPT(CA_PUBLIC_KEY_INFO, keyID, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CA_PUBLIC_KEY_INFO)
IMPLEMENT_ASN1_FUNCTIONS(CA_PUBLIC_KEY_INFO)



// from eac_asn1.c

static EC_KEY *
ecpkparameters2eckey(ASN1_TYPE *ec_params)
{
    EC_GROUP *group = NULL;
    EC_KEY *ec = NULL;
    int length, fail = 1;
    unsigned char *encoded = NULL;
    const unsigned char *p;

    if(!ec_params || ec_params->type != V_ASN1_SEQUENCE) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err;
    }

    /* unfortunately we need to re-pack and re-parse the ECPKPARAMETERS,
     * because there is no official API for using it directly (see
     * openssl/crypto/ec/ec.h) */
    length = i2d_ASN1_TYPE(ec_params, &encoded);
    p = encoded;
    if(length <= 0 || !d2i_ECPKParameters(&group, &p, length)) {
        printf("Could not decode EC parameters\n");
        goto err;
    }

    ec = EC_KEY_new();
    if(!ec || !EC_KEY_set_group(ec, group)) {
        printf("Could not initialize key object\n");
        goto err;
    }

    fail = 0;

err:
    if (group)
        EC_GROUP_free(group);
    OPENSSL_free(encoded);
    if (fail) {
        if (ec)
            EC_KEY_free(ec);
        ec = NULL;
    }
    return ec;
}

static DH *
dhparams2dh(ASN1_TYPE *dh_params)
{
    DH *dh = NULL;
    int length = 1;
    unsigned char *encoded = NULL;
    const unsigned char *p;

    if(!dh_params || dh_params->type != V_ASN1_SEQUENCE) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err;
    }

    /* unfortunately we need to re-pack and re-parse the DHparams,
     * because there is no official API for using it directly (see
     * openssl/crypto/dh/dh.h) */
    length = i2d_ASN1_TYPE(dh_params, &encoded);
    p = encoded;
    if(length <= 0 || !d2i_DHparams(&dh, &p, length)) {
        printf("Could not decode DH parameters\n");
        goto err;
    }

err:
    OPENSSL_free(encoded);
    return dh;
}

static EVP_PKEY *
aid2pkey(EVP_PKEY **key, ALGORITHM_IDENTIFIER *aid, BN_CTX *bn_ctx)
{
    EC_KEY *tmp_ec;
    DH *tmp_dh;
    EVP_PKEY *tmp_key = NULL, *ret = NULL;
    char obj_txt[32];
    int nid;

    /* If there is no key, allocate memory */
    if (!key || !*key) {
        tmp_key = EVP_PKEY_new();
        if (!tmp_key)
            goto err;
    } else
        tmp_key = *key;

    /* Extract actual parameters */
    nid = OBJ_obj2nid(aid->algorithm);
    if (       nid == NID_dhpublicnumber) {
        tmp_dh = dhparams2dh(aid->parameters);
        if(!tmp_dh) {
            printf("Could not decode DH key\n");
            goto err;
        }
        EVP_PKEY_set1_DH(tmp_key, tmp_dh);
        DH_free(tmp_dh);

    } else if (nid == NID_X9_62_id_ecPublicKey
            || nid == NID_ecka_dh_SessionKDF_DES3
            || nid == NID_ecka_dh_SessionKDF_AES128
            || nid == NID_ecka_dh_SessionKDF_AES192
            || nid == NID_ecka_dh_SessionKDF_AES256) {
        tmp_ec = ecpkparameters2eckey(aid->parameters);
        if(!tmp_ec) {
            printf("Could not decode EC key\n");
            goto err;
        }
        EVP_PKEY_set1_EC_KEY(tmp_key, tmp_ec);
        EC_KEY_free(tmp_ec);

    } else if (nid == NID_standardizedDomainParameters) {
        if(aid->parameters->type != V_ASN1_INTEGER) {
            printf("Invalid data\n");
            goto err;
        }
        if(!EVP_PKEY_set_std_dp(tmp_key,
                    ASN1_INTEGER_get(aid->parameters->value.integer))) {
            printf("Could not decode standardized domain parameter\n");
            goto err;
        }

    } else {
        OBJ_obj2txt(obj_txt, sizeof obj_txt, aid->algorithm, 0);
        printf("Unknown Identifier (%s) for %s\n", OBJ_nid2sn(nid), obj_txt);
    }

    ret = tmp_key;
    if (key)
        *key = tmp_key;

err:
    if (tmp_key && tmp_key != ret) {
        EVP_PKEY_free(tmp_key);
    }

    return ret;
}




#define get_ctx_by_id(ctx, stack, _id) \
{ \
    int __i, __count; \
    __count = sk_num((_STACK*) stack); \
    for (__i = 0; __i < __count; __i++) { \
        ctx = sk_value((_STACK*) stack, __i); \
        if (ctx && ctx->id == _id) { \
            break; \
        } \
    } \
    if (__i >= __count) { \
        ctx = NULL; \
    } \
}

#define get_ctx_by_keyID(ctx, stack, keyID, structure) \
{ \
    int __id; \
    if (keyID) { \
        __id = (int) ASN1_INTEGER_get(keyID); \
    }  \
    else { \
        __id = -1; \
    } \
    /* lookup the context in the stack identified by info's keyID */ \
    get_ctx_by_id(ctx, stack, __id); \
    \
    /* if no context was found, create one and push it onto the stack */ \
    if (!ctx) { \
        ctx = structure##_new(); \
        if (ctx) { \
            if (!sk_push((_STACK *) stack, ctx)) { \
                structure##_clear_free(ctx); \
                ctx = NULL; \
            } else { \
                /* created and pushed successfully, now initialize id */ \
                if(keyID) { \
                    ctx->id = __id; \
                } else { \
                    ctx->id = -1; \
                } \
            } \
        } \
    } \
}



/* ------------------ */


typedef struct datagrouphash_st {
    ASN1_INTEGER *dataGroupNumber;
    ASN1_OCTET_STRING *dataGroupHashValue;
} DG_HASH;

ASN1_SEQUENCE(DG_HASH) = {
    ASN1_SIMPLE(DG_HASH, dataGroupNumber, ASN1_INTEGER),
    ASN1_SIMPLE(DG_HASH, dataGroupHashValue, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(DG_HASH)

typedef struct ldsversioninfo_st {
    ASN1_PRINTABLESTRING *ldsVersion;
    ASN1_PRINTABLESTRING *unicodeVersion;
} LDS_VERSION_INFO;

ASN1_SEQUENCE(LDS_VERSION_INFO) = {
    ASN1_SIMPLE(LDS_VERSION_INFO, ldsVersion, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(LDS_VERSION_INFO, unicodeVersion, ASN1_PRINTABLESTRING),
} ASN1_SEQUENCE_END(LDS_VERSION_INFO)

DEFINE_STACK_OF(DG_HASH);

typedef struct sod_lds_st {
    ASN1_INTEGER *version;
    ALGORITHM_IDENTIFIER *hashAlgorithm;
    STACK_OF(DG_HASH) *dataGroupHashValues;
    LDS_VERSION_INFO *ldsVersionInfo;
} SOD_LDS;

ASN1_SEQUENCE(SOD_LDS) = {
    ASN1_SIMPLE(SOD_LDS, version, ASN1_INTEGER),
    ASN1_SIMPLE(SOD_LDS, hashAlgorithm, ALGORITHM_IDENTIFIER),
    ASN1_SEQUENCE_OF(SOD_LDS, dataGroupHashValues, DG_HASH),
    ASN1_OPT(SOD_LDS, ldsVersionInfo, LDS_VERSION_INFO)
} ASN1_SEQUENCE_END(SOD_LDS)

IMPLEMENT_ASN1_FUNCTIONS(SOD_LDS)


/* ------------------ */

static int CA_passive_authentication(const EPASS_CTX *epass_ctx, CMS_ContentInfo *ef_sod);

static int CA_verify_data_groups(const EPASS_CTX *epass_ctx, unsigned char *lds_data, size_t lds_len);

// TODO: CRL not yet used
int
CA_passive_authentication(const EPASS_CTX *epass_ctx, CMS_ContentInfo *ef_sod)
{
    X509 *ds_cert;
    X509_STORE *store;
    STACK_OF(X509) *dsc_list = NULL;
    unsigned long issuer_name_hash;
    int ret = 0;

    if(!ef_sod || !epass_ctx || !epass_ctx->lookup_csca_cert) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err_pa;
    }

    ASN1_OCTET_STRING **lds_octet_str_ptr = CMS_get0_content(ef_sod);
    if (!lds_octet_str_ptr || !(*lds_octet_str_ptr)) {
        printf("Failed to get signed content of SOD\n");
        goto err_pa;
    }

    /* Extract the DS certificates from the EF.SOD */
    dsc_list = CMS_get1_certs(ef_sod);
    if (!dsc_list) {
        printf("Failed to retrieve certificates from EF.SOD\n");
        goto err_pa;
    }

    /* NOTE: The following code assumes that there is only one certificate in
     * CMS structure. ds_cert is implicitly freed together with ds_certs. */
    if (sk_X509_num(dsc_list) != 1) {
        printf("Error: expected only 1 DSC for SOD\n");
        // TODO: free certs
        goto err_pa;
    }
    ds_cert = sk_X509_value(dsc_list, 0);
    if (!ds_cert) {
        printf("Error getting handle to DSC from list\n");
        // TODO: free certs (bcs. get1)
        goto err_pa;
    }

    /* Get the trust store with at least the csca certificate */
    issuer_name_hash = X509_issuer_name_hash(ds_cert);
    store = epass_ctx->lookup_csca_cert(issuer_name_hash);
    if (!store) {
        printf("Failed to retrieve CSCA truststore\n");
        // TODO: free certs (bcs. get1)
        goto err_pa;
    }

    /* Verify the signature and the certificate chain */
    if (!CMS_verify(ef_sod, dsc_list, store, NULL, NULL, 0)) {
        printf("Failed verification of SOD signature and certificate\n");
        // TODO: free certs (bcs. get1)
        goto err_pa;
    }

#ifdef SOD_SG_DEBUG
    printf("Successfully verified SOD signature based on DSC and CSCA\n");
#endif

    /* Verify the data group hashes */
    ret = CA_verify_data_groups(epass_ctx, (*lds_octet_str_ptr)->data, (*lds_octet_str_ptr)->length);

err_pa:
    if (dsc_list)
        sk_X509_free(dsc_list); // TODO: wasn't that wrong, bcs. get0 ?!

    // TODO: free certs (bcs. get1)

    return ret;
}


int CA_verify_data_groups(const EPASS_CTX *epass_ctx, unsigned char *lds_data, size_t lds_len) {
    int ret = 0;
    SOD_LDS *sod_lds = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;
    
    if(!lds_data || !epass_ctx) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err_dg;
    }

    const unsigned char *lds = lds_data; // to get rid of warning

    if(!d2i_SOD_LDS(&sod_lds, &lds, lds_len)) {
        printf("Could not decode LDS Security Object\n");
        goto err_dg;
    }

    evp_md_ctx = EVP_MD_CTX_create();
    if (!evp_md_ctx) {
        printf("Failed to allocated digest context (OOM)\n");
        goto err_dg;
    }

    // grab hash algorithm (TODO: could check for supported digest algos via switch over NID)
    ALGORITHM_IDENTIFIER *digest_algo = sod_lds->hashAlgorithm;
    const EVP_MD *evp_md = EVP_get_digestbyobj(digest_algo->algorithm);
    if (!evp_md) {
        printf("Failed to get digest algorithm of EF.SOD\n");
        goto err_dg;
    }
#ifdef SOD_SG_DEBUG
    printf("Digest algorithm: %d (SHA256 == %d)\n", EVP_MD_type(evp_md),
        EVP_MD_type(EVP_sha256()));
#endif

#ifdef SOD_SG_DEBUG
    printf("Number of DGs in set: %d\n", sk_DG_HASH_num(sod_lds->dataGroupHashValues));

     for (unsigned int i=0; i<sk_DG_HASH_num(sod_lds->dataGroupHashValues); i++) {
         DG_HASH *dg_hash = sk_DG_HASH_value(sod_lds->dataGroupHashValues, i);
         if (!dg_hash) break;
         printf("Got DG hash number: %d\n", ASN1_INTEGER_get(dg_hash->dataGroupNumber));
     }
#endif

    for (unsigned int i=0; i<epass_ctx->dg_num; i++) {
        DG *dg = epass_ctx->dgs[i];
        if(!dg) {
            printf("Unexpected: NULL DataGroup\n");
            goto err_dg;
        }

        unsigned char sigret[128];
        size_t siglen = sizeof(sigret);

        // grab respective hash from EF.SOD
        // todo: free?
#ifdef SOD_SG_DEBUG
        printf("Trying to get hash for DG: %d\n", dg->type);
#endif

        /* Note: there might not be a hash for every possible DG number, s.t.
         * a direct mapping from DG num to index is not possible;
         * also note that indexes start from 0, DG nums from 1
         * 
         * TODO: make more efficient
         */
        DG_HASH *dg_hash = NULL;
        for (int k=0; k<sk_DG_HASH_num(sod_lds->dataGroupHashValues); k++) {
            DG_HASH *tmp = sk_DG_HASH_value(sod_lds->dataGroupHashValues, k);
            if (!tmp) break;

            if (ASN1_INTEGER_get(tmp->dataGroupNumber) != dg->type) continue;
            //printf("Expected DG: %d, but got DG: %ld\n", dg->type, ASN1_INTEGER_get(dg_hash->dataGroupNumber));

            // found correct hash
            dg_hash = tmp;
            break;
        }
        if (!dg_hash) {
            printf("Failed to get DG hash from EF.SOD\n");
            goto err_dg;
        }

#ifdef SOD_SG_DEBUG
        printf("Got DG hash number: %d\n", ASN1_INTEGER_get(dg_hash->dataGroupNumber));
#endif

        // compute hash of DG
        // Important: hash is over (<tag>|<len>|<data>), not just over <data>
        if(!EVP_DigestInit(evp_md_ctx, evp_md)
            || !EVP_DigestUpdate(evp_md_ctx, dg->raw_data, dg->raw_len)
            || !EVP_DigestFinal(evp_md_ctx, sigret, &siglen)) {
            printf("DG hash recalculation failed for DG: %d\n", dg->type);
            goto err_dg;
        }

        // verify by comparing the hashes
        if (siglen != ASN1_STRING_length(dg_hash->dataGroupHashValue)) {
            printf("Length mismatch for DG hash, expected: %ld, SOD contains: %d\n", siglen, ASN1_STRING_length(dg_hash->dataGroupHashValue));
            goto err_dg;
        }
        if (memcmp(ASN1_STRING_get0_data(dg_hash->dataGroupHashValue), sigret, siglen) != 0) {
            printf("Hash mismatch for DG: %d\n", dg->type);
            goto err_dg;
        }

#ifdef SOD_SG_DEBUG
        printf("Successful hash check\n");
#endif
    }

    ret = 1;

err_dg:
    if (sod_lds)
        SOD_LDS_free(sod_lds);
    if (evp_md_ctx)
        EVP_MD_CTX_free(evp_md_ctx);

    return ret;
}

int
FIDO_SGX_parse_document_security_object(const unsigned char *ef_sod,
            size_t ef_sod_len, EPASS_CTX *epass_ctx)
{
    CMS_ContentInfo *cms = NULL;
    int r = 0;

    if(!ef_sod || !epass_ctx) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err_sod;
    }

    /* Currently following encoding of client's Java library ...
     * <tag> (variable) | <len> (4B or variable) | CMS with signed PKCS7 data(?)

     * tag was 0x77 == EF_SOD_TAG
     * len was 0x82, i.e. 0x80 | 0x02, i.e., 2 additional length bytes -> 3 B
     * 
     * => 1 tag Byte (0x77), 3 length Bytes (0x82, 0x06, 0x20)
     */
    const unsigned char *p = ef_sod;
    // TODO: flexible length parsing (cf. DG parsing)
    p += (1 + 3); // skip tag and len


    if (!d2i_CMS_ContentInfo(&cms, &p, ef_sod_len - 4)) {
        printf("SOD: getting CMS_ContentInfo failed\n");
        goto err_sod;
    }
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_signed) {
        printf("SOD: obj2nid of CMS type is not the expected signed PKCS7, but rather: %d\n", OBJ_obj2nid(CMS_get0_type(cms)));
        goto err_sod;
    }

    if (OBJ_obj2nid(CMS_get0_eContentType(cms)) != NID_ldsSecurityObject) {
        printf("Wrong encoded content type\n");
        goto err_sod;
    }

    if (CA_passive_authentication(epass_ctx, cms) != 1) {
        printf("Failed to perform passive authentication\n");
        goto err_sod;
    }

    r = 1;

err_sod:
    if (cms)
        CMS_ContentInfo_free(cms);

    return r;
}

int
FIDO_SGX_parse_dg14_ca_infos(EPASS_CTX *epass_ctx, const DG *dg14) {
    int ret = 0;
    if(!epass_ctx || !dg14) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err_dg14;
    }

    const unsigned char *in = dg14->data;

    if(dg14->type != DG14 || !in) goto err_dg14;

    // based on OpenPACE's EAC_CTX_init_ef_cardaccess()
    ASN1_INTEGER *i = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *pubkey;
    size_t pubkey_len;
    CA_CTX *ca_ctx = NULL;
#if 0 // CAv2 (ePassport uses v1)
    CA_DP_INFO *tmp_ca_dp_info = NULL;
#endif
    CA_INFO *tmp_ca_info = NULL;
    CA_PUBLIC_KEY_INFO *ca_public_key_info = NULL;
    char obj_txt[32];
    const unsigned char *info_start;
    int tag, class, nid;
    long data_len, info_len;
    unsigned int todo = 0;

    /* We need to manually extract all members of the SET OF SecurityInfos,
     * because some files contain junk and look something like this:
     *
     *      SET { SecurityInfo, ..., SecurityInfo } , junk
     *
     * As far as we know, there is no way of telling OpenSSL to simply ignore
     * the junk in d2i_* functions. That's why we iterate manually through
     * the set */

    int e = ASN1_get_object(&in, &data_len, &tag, &class, dg14->len);
    if(0x80 & e) {
        printf("ASN1_get_object() failed\n");
        printf("error ret value: %#x\n", e ^ 0x80);
        if (e == 0xa0) printf("dg14->len too small\n");
        goto err_dg14;
    }
    if(tag != V_ASN1_SET) {
        printf("Invalid tag: %d instead of %d\n", tag, V_ASN1_SET);
        goto err_dg14;
    }

    todo = data_len;

    while (todo > 0) {
        info_start = in;

        if (!(ASN1_get_object(&in, &data_len, &tag, &class, todo))
                || tag != V_ASN1_SEQUENCE) {
            /* we've reached the junk */
            break;
        }

        info_len = (in-info_start) + data_len;

        if(!d2i_ASN1_OBJECT(&oid, &in, data_len)) {
            printf("Invalid oid\n");
            goto err_dg14;
        }

        in = info_start;

        nid = OBJ_obj2nid(oid);
        if (nid == NID_id_CA_DH_3DES_CBC_CBC
                || nid == NID_id_CA_DH_AES_CBC_CMAC_128
                || nid == NID_id_CA_DH_AES_CBC_CMAC_192
                || nid == NID_id_CA_DH_AES_CBC_CMAC_256
                || nid == NID_id_CA_ECDH_3DES_CBC_CBC
                || nid == NID_id_CA_ECDH_AES_CBC_CMAC_128
                || nid == NID_id_CA_ECDH_AES_CBC_CMAC_192
                || nid == NID_id_CA_ECDH_AES_CBC_CMAC_256) {
            /* CAInfo */
            if(!d2i_CA_INFO(&tmp_ca_info, &in, info_len)) {
                printf("Could not decode CA info\n");
                goto err_dg14;
            }

            /* lookup or create a ca context */
#ifdef SOD_SG_DEBUG
            printf("keyID: %ld #1 (nid: %d)\n", ASN1_INTEGER_get(tmp_ca_info->keyID), nid);
            printf("NID_id_CA_ECDH_3DES_CBC_CBC: %d\n", NID_id_CA_ECDH_3DES_CBC_CBC);
            printf("NID_id_CA_ECDH_AES_CBC_CMAC_128: %d\n", NID_id_CA_ECDH_AES_CBC_CMAC_128);
#endif
            get_ctx_by_keyID(ca_ctx, epass_ctx->ca_ctxs, tmp_ca_info->keyID, CA_CTX);
            if (!ca_ctx) {
                goto err_dg14;
            }

            ca_ctx->version = (unsigned char) ASN1_INTEGER_get(tmp_ca_info->version);
            if (ca_ctx->version <= 0 || ca_ctx->version > 2
                    || !CA_CTX_set_protocol(ca_ctx, nid))
                goto err_dg14;

        } else if (nid == NID_id_PK_DH
                || nid == NID_id_PK_ECDH) {
            /* ChipAuthenticationPublicKeyInfo */
            if(!d2i_CA_PUBLIC_KEY_INFO(&ca_public_key_info, &in, info_len)) {
                printf("Could not decode CA PK domain parameter info\n");
                goto err_dg14;
            }

//            /* lookup or create a ca context */
//            if (!tmp_ca_info) {
//                goto err_dg14;
//            }

#ifdef SOD_SG_DEBUG
            printf("keyID from CA_PUB_KEY_INFO: %ld #2\n", ASN1_INTEGER_get(ca_public_key_info->keyID));
#endif
            get_ctx_by_keyID(ca_ctx, epass_ctx->ca_ctxs, ca_public_key_info->keyID, CA_CTX);
            if (!ca_ctx) {
                goto err_dg14;
            }

#ifdef SOD_SG_DEBUG
            printf("Will try to fill peer_pubkey? #1 (algo id: %d)\n",
                OBJ_obj2nid(ca_public_key_info->chipAuthenticationPublicKeyInfo->algorithmIdentifier->algorithm));
            printf("ECDH: %d, DH: %d\n", NID_id_PK_ECDH, NID_id_PK_DH);
#endif
            // aid2pkey does not use bn_ctx as it seems
            // create key template and fill with algorithm information
            if (!aid2pkey(&ca_ctx->ka_ctx->peer_pubkey,
                        ca_public_key_info->chipAuthenticationPublicKeyInfo->algorithmIdentifier,
                        NULL))
                goto err_dg14;

            // use same later for potential ephemeral key
            if (!aid2pkey(&ca_ctx->ka_ctx->key,
                         ca_public_key_info->chipAuthenticationPublicKeyInfo->algorithmIdentifier,
                        NULL))
                goto err_dg14;

            if (nid == NID_id_PK_DH) {
                /* FIXME the public key for DH is actually an ASN.1
                 * UNSIGNED INTEGER, which is an ASN.1 INTEGER that is
                 * always positive. Parsing the unsigned integer should be
                 * done in EVP_PKEY_set_key. */
                const unsigned char *p = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->data;
                if(!d2i_ASN1_UINTEGER(&i, &p,
                            ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->length)) {
                    printf("Could not decode CA PK\n");
                    goto err_dg14;
                }
                pubkey = i->data;
                pubkey_len = i->length;
            } else {
                pubkey = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->data;
                pubkey_len = ca_public_key_info->chipAuthenticationPublicKeyInfo->subjectPublicKey->length;
            }

            // BN_CTX is optional; will use a tmp. one if NULL
#ifdef SOD_SG_DEBUG
            printf("Will try to fill peer_pubkey? #2 (pubkey: %p, len: %lu)\n",
                pubkey, pubkey_len);
#endif

#ifdef SOD_SG_DEBUG
            printf("peer_pubkey before #2: %p\n", ca_ctx->ka_ctx->peer_pubkey);
#endif
            // set actual public key of ePassport into template
            if (!EVP_PKEY_set_keys(ca_ctx->ka_ctx->peer_pubkey, NULL, 0, pubkey, pubkey_len, NULL))
                goto err_dg14;
#ifdef SOD_SG_DEBUG
            printf("peer_pubkey after #2: %p\n", ca_ctx->ka_ctx->peer_pubkey);
#endif

        } else {
#ifdef SOD_SG_DEBUG
            OBJ_obj2txt(obj_txt, sizeof obj_txt, oid, 0);
            printf("Unsupported/Unused Identifier (%s) for %s\n", OBJ_nid2sn(nid), obj_txt);
#endif
        }

        /* if we have created the first CA context, use it as default */
        if (!epass_ctx->ca_ctx)
            epass_ctx->ca_ctx = ca_ctx;

        todo -= info_len;
        in = info_start+info_len;
    }

    ret = 1;

err_dg14:
    // TODO: free even more?
    if (oid)
        ASN1_OBJECT_free(oid);
    if (tmp_ca_info)
        CA_INFO_free(tmp_ca_info);
    if (i)
        ASN1_INTEGER_free(i);
#if 0 // CAv2 (ePassport uses v1)
    if (tmp_ca_dp_info)
        CA_DP_INFO_free(tmp_ca_dp_info);
#endif
    if (ca_public_key_info)
        CA_PUBLIC_KEY_INFO_free(ca_public_key_info);

    return ret;
}

FORM_DG1 *
FIDO_SGX_parse_dg1(EPASS_CTX *epass_ctx, const DG *dg1) {
    FORM_DG1 *fdg1 = NULL, *tmp = NULL;

    if(!epass_ctx || !dg1 || dg1->type != DG1 || !dg1->data) {
        printf("Invalid arguments (%s:%d/%s)\n", __FILE__, __LINE__, __func__);
        goto err_fdg1;
    }

    tmp = malloc(sizeof(*fdg1));
    if (!tmp) {
        printf("OOM\n");
        goto err_fdg1;
    }

    /* TODO: more advanced parsing, e.g., via document type (or whatever) */
    switch (dg1->len) {
        case sizeof(struct dg1_td1):
            tmp->format = TD1;
            tmp->td_data.td1_data = (struct dg1_td1 *)dg1->data;
            break;
        case sizeof(struct dg1_td2):
            tmp->format = TD2;
            tmp->td_data.td2_data = (struct dg1_td2 *)dg1->data;
            break;
        case sizeof(struct dg1_td3):
            tmp->format = TD3;
            tmp->td_data.td3_data = (struct dg1_td3 *)dg1->data;
            break;
        default:
            printf("Unknown DG1 format of length: %ld (%0lx)\n", dg1->len, dg1->len);
            goto err_fdg1;
    }

    fdg1 = tmp;
    tmp = NULL;

err_fdg1:
    if (tmp)
        free(tmp);

    return fdg1;
}

static void
FIDO_SGX_print_array(const char *prefix, const int8_t *data, size_t length) {
    if(!data) return;
    if(prefix) printf("%s", prefix);
    for (size_t i=0; i<length; i++) printf(" %0x", data[i]);
    printf("\n");
}

int
FIDO_SGX_print_form_dg1(const FORM_DG1 *fdg1) {
    int ret = 0;
    if (!fdg1) goto err_print;
    switch(fdg1->format) {
        case TD1: {
#define DATA fdg1->td_data.td1_data
            printf("Format: TD1\n");
            FIDO_SGX_print_array("document_code:", DATA->document_code, sizeof(DATA->document_code));
            FIDO_SGX_print_array("issuing_state_org:", DATA->issuing_state_org, sizeof(DATA->issuing_state_org));
            FIDO_SGX_print_array("document_number:", DATA->document_number, sizeof(DATA->document_number));
            FIDO_SGX_print_array("check_digit_docno:", DATA->check_digit_docno, sizeof(DATA->check_digit_docno));
            FIDO_SGX_print_array("optional_data_docno:", DATA->optional_data_docno, sizeof(DATA->optional_data_docno));
            FIDO_SGX_print_array("date_of_birth:", DATA->date_of_birth, sizeof(DATA->date_of_birth));
            FIDO_SGX_print_array("check_digit_dateob:", DATA->check_digit_dateob, sizeof(DATA->check_digit_dateob));
            FIDO_SGX_print_array("sex:", DATA->sex, sizeof(DATA->sex));
            FIDO_SGX_print_array("date_of_expiry:", DATA->date_of_expiry, sizeof(DATA->date_of_expiry));
            FIDO_SGX_print_array("check_digit_dateoe:", DATA->check_digit_dateoe, sizeof(DATA->check_digit_dateoe));
            FIDO_SGX_print_array("nationality:", DATA->nationality, sizeof(DATA->nationality));
            FIDO_SGX_print_array("optional_data:", DATA->optional_data, sizeof(DATA->optional_data));
            FIDO_SGX_print_array("comp_check_digit:", DATA->comp_check_digit, sizeof(DATA->comp_check_digit));
            FIDO_SGX_print_array("name_of_holder:", DATA->name_of_holder, sizeof(DATA->name_of_holder));
#undef DATA
            break;
        }
        case TD2:
#define DATA fdg1->td_data.td2_data
            printf("Format: TD2\n");
            FIDO_SGX_print_array("document_code:", DATA->document_code, sizeof(DATA->document_code));
            FIDO_SGX_print_array("issuing_state_org:", DATA->issuing_state_org, sizeof(DATA->issuing_state_org));
            FIDO_SGX_print_array("name_of_holder:", DATA->name_of_holder, sizeof(DATA->name_of_holder));
            FIDO_SGX_print_array("document_number:", DATA->document_number, sizeof(DATA->document_number));
            FIDO_SGX_print_array("check_digit_docno:", DATA->check_digit_docno, sizeof(DATA->check_digit_docno));
            FIDO_SGX_print_array("nationality:", DATA->nationality, sizeof(DATA->nationality));
            FIDO_SGX_print_array("date_of_birth:", DATA->date_of_birth, sizeof(DATA->date_of_birth));
            FIDO_SGX_print_array("check_digit_dateob:", DATA->check_digit_dateob, sizeof(DATA->check_digit_dateob));
            FIDO_SGX_print_array("sex:", DATA->sex, sizeof(DATA->sex));
            FIDO_SGX_print_array("date_of_expiry:", DATA->date_of_expiry, sizeof(DATA->date_of_expiry));
            FIDO_SGX_print_array("check_digit_dateoe:", DATA->check_digit_dateoe, sizeof(DATA->check_digit_dateoe));
            FIDO_SGX_print_array("optional_data_plus_filler:", DATA->optional_data_plus_filler, sizeof(DATA->optional_data_plus_filler));
            FIDO_SGX_print_array("comp_check_digit:", DATA->comp_check_digit, sizeof(DATA->comp_check_digit));
#undef DATA
            break;
        case TD3:
            printf("Format: TD3\n");
#define DATA fdg1->td_data.td3_data
            FIDO_SGX_print_array("document_code:", DATA->document_code, sizeof(DATA->document_code));
            FIDO_SGX_print_array("issuing_state_org:", DATA->issuing_state_org, sizeof(DATA->issuing_state_org));
            FIDO_SGX_print_array("name_of_holder:", DATA->name_of_holder, sizeof(DATA->name_of_holder));
            FIDO_SGX_print_array("document_number:", DATA->document_number, sizeof(DATA->document_number));
            FIDO_SGX_print_array("check_digit_docno:", DATA->check_digit_docno, sizeof(DATA->check_digit_docno));
            FIDO_SGX_print_array("nationality:", DATA->nationality, sizeof(DATA->nationality));
            FIDO_SGX_print_array("date_of_birth:", DATA->date_of_birth, sizeof(DATA->date_of_birth));
            FIDO_SGX_print_array("check_digit_dateob:", DATA->check_digit_dateob, sizeof(DATA->check_digit_dateob));
            FIDO_SGX_print_array("sex:", DATA->sex, sizeof(DATA->sex));
            FIDO_SGX_print_array("date_of_expiry:", DATA->date_of_expiry, sizeof(DATA->date_of_expiry));
            FIDO_SGX_print_array("check_digit_dateoe:", DATA->check_digit_dateoe, sizeof(DATA->check_digit_dateoe));
            FIDO_SGX_print_array("optional_data:", DATA->optional_data, sizeof(DATA->optional_data));
            FIDO_SGX_print_array("check_digit:", DATA->check_digit, sizeof(DATA->check_digit));
            FIDO_SGX_print_array("comp_check_digit:", DATA->comp_check_digit, sizeof(DATA->comp_check_digit));
#undef DATA
            break;
        default:
            printf("Unknown format: %d\n", fdg1->format);
            goto err_print;
    }
    ret = 1;
err_print:
    return ret;
}
