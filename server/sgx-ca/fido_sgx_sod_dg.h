#ifndef _FIDO_SGX_SOD_DG_H_
#define _FIDO_SGX_SOD_DG_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <openssl/ossl_typ.h>

#include <openssl/safestack.h>

#include <openssl/evp.h>
#include <openssl/cmac.h>

enum TD_Format { TD1=1, TD2, TD3, OTHERS };

// TD1 (len = 90, 0x5a)
struct dg1_td1 {
    int8_t document_code[2];
    int8_t issuing_state_org[3];
    int8_t document_number[9];
    int8_t check_digit_docno[1];
    int8_t optional_data_docno[15];
    int8_t date_of_birth[6];
    int8_t check_digit_dateob[1];
    int8_t sex[1];
    int8_t date_of_expiry[6];
    int8_t check_digit_dateoe[1];
    int8_t nationality[3];
    int8_t optional_data[11];
    int8_t comp_check_digit[1];
    int8_t name_of_holder[30];
};

// TD2 (len = 72, 0x48)
struct dg1_td2 {
    int8_t document_code[2];
    int8_t issuing_state_org[3];
    int8_t name_of_holder[31];
    int8_t document_number[9];
    int8_t check_digit_docno[1];
    int8_t nationality[3];
    int8_t date_of_birth[6];
    int8_t check_digit_dateob[1];
    int8_t sex[1];
    int8_t date_of_expiry[6];
    int8_t check_digit_dateoe[1];    
    int8_t optional_data_plus_filler[7];
    int8_t comp_check_digit[1];
};

// TD3 (len = 88, 0x58)
struct dg1_td3 {
    int8_t document_code[2];
    int8_t issuing_state_org[3];
    int8_t name_of_holder[39];
    int8_t document_number[9];
    int8_t check_digit_docno[1];
    int8_t nationality[3];
    int8_t date_of_birth[6];
    int8_t check_digit_dateob[1];
    int8_t sex[1];
    int8_t date_of_expiry[6];
    int8_t check_digit_dateoe[1];
    int8_t optional_data[14];
    int8_t check_digit[1];
    int8_t comp_check_digit[1];
};

typedef struct formatted_datagroup1 {
    enum TD_Format format;
    union {
        const struct dg1_td1 *td1_data;
        const struct dg1_td2 *td2_data;
        const struct dg1_td3 *td3_data;
    } td_data;
} FORM_DG1;



enum DG_Type { DG1 = 1, DG14 = 14 };

typedef struct data_group {
    unsigned char *data;
    size_t  len;
    enum DG_Type type;
    // todo
    unsigned char *raw_data; // with tag, len
    size_t raw_len; // with tag_len
} DG;

/** @brief callback for finding the X.509 trust anchor */
typedef X509_STORE * (*X509_lookup_csca_cert) (unsigned long issuer_name_hash);

/**
 * @brief Context for a key agreement and subsequent derivation of session
 * keys.
 * @note The key agreement itself is done via an underlying DH or ECDH.
 */
typedef struct ka_ctx {
        /** @brief Digest to use for key derivation */
        const EVP_MD * md;
        /** @brief Digest's engine */
        ENGINE * md_engine;
        /** @brief Context for CMAC */
        CMAC_CTX * cmac_ctx;
        /** @brief Cipher to use for encryption/decryption */
        const EVP_CIPHER * cipher;
        /** @brief Cipher's engine */
        ENGINE * cipher_engine;
        /** @brief Initialisation vector for encryption/decryption */
        unsigned char * iv;
        /** @brief Length of the computed key for the message authentication code */
        int mac_keylen;
        /** @brief Length of the computed key for the encryption/decryption */
        int enc_keylen;

         /**
         * @brief Generates a key pair for key agreement.
         *
         * @param[in] key Object for key generation, usually \c &KA_CTX.key
         * @param[in] bn_ctx (optional)
         *
         * @return Public key or NULL in case of an error
         */
        BUF_MEM * (*generate_key)(EVP_PKEY *key, BN_CTX *bn_ctx);
        /**
         * @brief Completes a key agreement by computing the shared secret
         *
         * @param[in] key Object for key computation, usually \c &KA_CTX.key
         * @param[in] in Public key from the other party
         * @param[in] bn_ctx (optional)
         *
         * @return Shared secret or NULL in case of an error
         */
        BUF_MEM * (*compute_key)(EVP_PKEY *key, const BUF_MEM *in, BN_CTX *bn_ctx);

        /** @brief Container for the key pair used for key agreement */
        EVP_PKEY *key;

        /** @brief Container for the peer's public key for key agreement */
        EVP_PKEY *peer_pubkey;

        /** @brief Shared secret computed during the key agreement protocol */
        BUF_MEM *shared_secret;
        /** @brief Symmetric key used for encryption/decryption. Derived from KA_CTX.shared_secret. */
        BUF_MEM *k_enc;
        /** @brief Symmetric key used for integrity protection. Derived from KA_CTX.shared_secret. */
        BUF_MEM *k_mac;
} KA_CTX;

/** @brief Context for the Chip Authentication protocol */
typedef struct ca_ctx {
    /** @brief (currently unused) Version of the CA protocol, MUST be 1 or 2 */
    unsigned char version;
    /** @brief Identifier of the protocol's OID specifying the exact CA parameters to use.
     *
     * Accepts the following values:
     * - \c NID_id_CA_DH_3DES_CBC_CBC
     * - \c NID_id_CA_DH_AES_CBC_CMAC_128
     * - \c NID_id_CA_DH_AES_CBC_CMAC_192
     * - \c NID_id_CA_DH_AES_CBC_CMAC_256
     * - \c NID_id_CA_ECDH_3DES_CBC_CBC
     * - \c NID_id_CA_ECDH_AES_CBC_CMAC_128
     * - \c NID_id_CA_ECDH_AES_CBC_CMAC_192
     * - \c NID_id_CA_ECDH_AES_CBC_CMAC_256
     */
    int protocol;
    /** @brief identifier of this CA context */
    int id;
    /** @brief Key agreement object used with the PICC's private key */
    KA_CTX *ka_ctx;
} CA_CTX;

#define MAX_DGS 16

typedef struct epass_ctx {
    CA_CTX *ca_ctx; // current default/selected
    KA_CTX *key_ctx; // current KA context for encrypt/decrypt/mac/verify (todo)
    STACK_OF(CA_CTX *) ca_ctxs;
    /** @brief callback for finding the X.509 trust anchor */
    X509_lookup_csca_cert lookup_csca_cert;
    /** @brief Send sequence counter */
    BIGNUM *ssc; //todo
    unsigned int dg_num;
    DG *dgs[MAX_DGS];
} EPASS_CTX;

int
FIDO_SGX_parse_document_security_object(const unsigned char *ef_sod,
            size_t ef_sod_len, EPASS_CTX *epass_ctx);

int
FIDO_SGX_parse_dg14_ca_infos(EPASS_CTX *epass_ctx, const DG *dg14);

/* Warning:  Does not copy the content of dg1 at the moment */
FORM_DG1 *
FIDO_SGX_parse_dg1(EPASS_CTX *epass_ctx, const DG *dg1);

int
FIDO_SGX_print_form_dg1(const FORM_DG1 *fdg1);

#if defined(__cplusplus)
}
#endif

#endif /* !_FIDO_SGX_SOD_DG_H_ */
