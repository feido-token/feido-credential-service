#include "feido_kdf.h"

#include <openssl/hmac.h>

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "Enclave.h"

#include "Enclave_debug.h"

#ifdef FEIDO_GLOBAL_DEBUG
#define DEBUG_FEIDO_KDF
#endif

static bool feido_derive_ecc_private_key(KDF_INFO kdf_info, unsigned char *out_key, unsigned int *inout_keylen);

// todo: init and share across enclaves 
static uint8_t hmac_key[32] = {0,};

EVP_PKEY *feido_derive_ecc_key_pair(KDF_INFO kdf_info) {
    EVP_PKEY *key_pair = NULL;
    EC_KEY *ec_key_pair = NULL;
    BIGNUM *priv_key = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;

    /* Derived SEED */
    unsigned int key_len = EVP_MD_size(EVP_sha256());
    unsigned char *key_buf = (unsigned char *)OPENSSL_zalloc(key_len);
    if (!key_buf) goto err;

    if(!feido_derive_ecc_private_key(kdf_info, key_buf, &key_len)) goto err;

    /* Private EC Key */
    ec_key_pair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key_pair) goto err;

    priv_key = BN_bin2bn(key_buf, key_len, NULL);
    if (!priv_key) goto err;

#ifdef DEBUG_FEIDO_KDF
    printf("Hex of private EC key: %s\n", BN_bn2hex(priv_key));
#endif

    if (!EC_KEY_set_private_key(ec_key_pair, priv_key)) goto err;

    /* Public EC Key */
    group = EC_KEY_get0_group(ec_key_pair);

    pub_key = EC_POINT_new(group);
    if (!pub_key) goto err;

    // from OpenSSL 1.1.1 source (ec_key.c)
    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL))
        goto err;

    EC_KEY_set_public_key(ec_key_pair, pub_key);

    if (!EC_KEY_check_key(ec_key_pair)) {
        printf("Error: get generated EC key pair is not valid\n");
        goto err;
    }

    key_pair = EVP_PKEY_new();
    if (!key_pair) goto err;

    EVP_PKEY_set1_EC_KEY(key_pair, ec_key_pair);

err:
    /* TODO: some use references counting to avoid use-after-free, but maybe
     *       there is still something wrong here? */
    if (pub_key) EC_POINT_free(pub_key);
    if (priv_key) BN_free(priv_key);
    if (ec_key_pair) EC_KEY_free(ec_key_pair);
    if (key_buf) OPENSSL_free(key_buf);

    return key_pair;
}

// static
bool feido_add_personal_data(HMAC_CTX *hmctx, FORM_DG1 *personal_data) {
    bool ret = false;
    if (!hmctx || !personal_data) goto err;

    unsigned char *name, *birth, *sex, *issuing_state;
    size_t len_name, len_birth, len_sex, len_issuing_state;

    switch (personal_data->format)
    {
    case TD1: {
        const struct dg1_td1 *data = personal_data->td_data.td1_data;
        name = (unsigned char *)data->name_of_holder;
        len_name = sizeof(data->name_of_holder);
        birth = (unsigned char *)data->date_of_birth;
        len_birth = sizeof(data->date_of_birth);
        sex = (unsigned char *)data->sex;
        len_sex = sizeof(data->sex);
        issuing_state = (unsigned char *)data->issuing_state_org;
        len_issuing_state = sizeof(data->issuing_state_org);
        break;
    }

    case TD2: {
        const struct dg1_td2 *data = personal_data->td_data.td2_data;
        name = (unsigned char *)data->name_of_holder;
        len_name = sizeof(data->name_of_holder);
        birth = (unsigned char *)data->date_of_birth;
        len_birth = sizeof(data->date_of_birth);
        sex = (unsigned char *)data->sex;
        len_sex = sizeof(data->sex);
        issuing_state = (unsigned char *)data->issuing_state_org;
        len_issuing_state = sizeof(data->issuing_state_org);
        break;
    }

    case TD3: {
        const struct dg1_td3 *data = personal_data->td_data.td3_data;
        name = (unsigned char *)data->name_of_holder;
        len_name = sizeof(data->name_of_holder);
        birth = (unsigned char *)data->date_of_birth;
        len_birth = sizeof(data->date_of_birth);
        sex = (unsigned char *)data->sex;
        len_sex = sizeof(data->sex);
        issuing_state = (unsigned char *)data->issuing_state_org;
        len_issuing_state = sizeof(data->issuing_state_org);
        break;
    }

    default:
        goto err;
        break;
    }

    if(1 != HMAC_Update(hmctx, name, len_name)) goto err;
    if(1 != HMAC_Update(hmctx, birth, len_birth)) goto err;
    if(1 != HMAC_Update(hmctx, sex, len_sex)) goto err;
    if(1 != HMAC_Update(hmctx, issuing_state, len_issuing_state)) goto err;
    ret = true;
err:
    return ret;
}

static bool feido_derive_ecc_private_key(KDF_INFO kdf_info, unsigned char *out_key, unsigned int *inout_keylen) {
    HMAC_CTX *hmctx = NULL;
    bool ret = false;
    const int KEY_OUT_LEN = EVP_MD_size(EVP_sha256());
    if (KEY_OUT_LEN < 0) goto err;

    if (!out_key || !inout_keylen || (*inout_keylen < (unsigned int)KEY_OUT_LEN) ) goto err;

	if((hmctx = HMAC_CTX_new()) == NULL) goto err;
	if(1 != HMAC_Init_ex(hmctx, hmac_key, sizeof(hmac_key), EVP_sha256(), NULL)) goto err;

    /* key := HMAC(hmac_key, service_name|name|birth|sex|issuingState) */
    // TODO: place of birth (from DG11)

	if(1 != HMAC_Update(hmctx, (unsigned char *)kdf_info.service_name, strlen(kdf_info.service_name))) goto err;

    if(!feido_add_personal_data(hmctx, kdf_info.personal_data)) goto err;

    if(1 != HMAC_Final(hmctx, out_key, inout_keylen)) goto err;

    ret = true;

err:
    if (hmctx) HMAC_CTX_free(hmctx);
    return ret;
}
