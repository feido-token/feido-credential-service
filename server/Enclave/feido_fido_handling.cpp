#include "feido_fido_handling.h"

#include <string>

#include "fido_sgx.pb.h"

#include "Enclave.h"

#include "feido_kdf.h"

#include <cbor.h>

#include "Enclave_debug.h"

#ifdef FEIDO_GLOBAL_DEBUG
#define FEIDO_FIDO_HNDL_DEBUG
#endif

/* based on https://www.w3.org/TR/webauthn-2/ */
typedef struct {
    uint8_t aaguid[16];
    uint16_t credentialIdLength_be; // Warning: big endian
    void *credentialId; // len: credentialIdLength_be
    void *credentialPublicKey; // variable length, encoded in *COSE_Key format using CTAP2 canonical CBOR encoding* form
} __attribute__((packed)) FIDO_ACD;

typedef struct {
    uint8_t rpIdHash[32];
    uint8_t flags;
    uint32_t signCount_be; // WARNING: BigEndian
//    void *attestedCredentialData; // variable length, optional
//    void *extensions; // variable length, optional
} __attribute__((packed)) FIDO_AD;
/* */

enum att_type { ATT_NONE };

static size_t FEIDO_FIDO_calculate_ad_buffer_length(FEIDO_FIDO_CTX *ctx, fido_sgx::AuthenticatorData *ad) {
    if (!ctx || !ad) return 0;
    size_t buf_len = 0;
    FIDO_AD ad_struct;

    // direct fix-length fields
    buf_len += sizeof(ad_struct.rpIdHash);
    buf_len += sizeof(ad_struct.flags);
    buf_len += sizeof(ad_struct.signCount_be);

    // variable length acd
    if (ad->has_acd()) {
        FIDO_ACD acd_struct;
        // fix-length
        buf_len += sizeof(acd_struct.aaguid);
        buf_len += sizeof(acd_struct.credentialIdLength_be);

        // variable length: credentialId
        uint16_t cred_len = ad->acd().credentialidlength_be();
        cred_len = __builtin_bswap16(cred_len);
        buf_len += cred_len;

        // variable length: credentialPublicKey
        buf_len += ad->acd().credentialpublickey().length();
    }

    return buf_len;
}

static std::string *FEIDO_FIDO_craft_attestationObject(FEIDO_FIDO_CTX *ctx, fido_sgx::AuthenticatorData *ad, enum att_type attestation_type) {
    if (!ctx || !ad) {
        printf("Invalid arguments @%s\n", __func__);
        return NULL;
    }
    if (attestation_type != ATT_NONE) {
        printf("Unsupported attestation type\n");
        return NULL;
    }

    /* "None" attestation object aka CBOR map:
     * "authData" -> bytes,
     * "fmt" -> "none",
     * "attStmt" -> <emptyMap>,
     */
    uint8_t buf[256]; // TODO: what size?
    CborEncoder encoder, mapEncoder, nestedMapEncoder;

    size_t result_len;
    std::string *corse_pkey = NULL;

    uint8_t *ad_buffer = NULL, *ad_p = NULL;
    size_t ad_buf_len = 0, ad_buf_left = 0;

    size_t tmpLen;
    FIDO_ACD acd_data;
    FIDO_AD ad_data;

    //
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    if(CborNoError != cbor_encoder_create_map(&encoder, &mapEncoder, 3)) goto err_ao;

    /* Prepare AD/ACD data */
    ad_buf_len = FEIDO_FIDO_calculate_ad_buffer_length(ctx, ad);
    if (!ad_buf_len) goto err_ao;
#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Calculated ad_buf_len: %lu\n", ad_buf_len);
#endif

    ad_buffer = (uint8_t *)malloc(ad_buf_len);
    if (!ad_buffer) goto err_ao;

    ad_p = ad_buffer;
    ad_buf_left = ad_buf_len;

    // direct AD fields
    tmpLen = sizeof(ad_data.rpIdHash);
    if (tmpLen != ad->rpidhash().length()) goto err_ao;
    memcpy(ad_data.rpIdHash, ad->rpidhash().data(), tmpLen);

    ad_data.flags = ad->flags();
    tmpLen += sizeof(ad_data.flags);

    ad_data.signCount_be = ad->signcount_be();
    tmpLen += sizeof(ad_data.signCount_be);

    if (tmpLen > ad_buf_left) goto err_ao;

    memcpy(ad_p, &ad_data, tmpLen);
    ad_buf_left -= tmpLen;
    ad_p += tmpLen;

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Updated ad_buf_left: %lu\n", ad_buf_left);
#endif

    // indirect fields: ACD

    // fix
    tmpLen = ad->acd().aaguid().length();
    if (tmpLen != sizeof(acd_data.aaguid) || tmpLen > ad_buf_left) goto err_ao;
    memcpy(ad_p, ad->acd().aaguid().data(), tmpLen);
    ad_buf_left -= tmpLen;
    ad_p += tmpLen;

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Updated ad_buf_left: %lu\n", ad_buf_left);
#endif

    tmpLen = sizeof(acd_data.credentialIdLength_be);
    if (tmpLen > ad_buf_left) goto err_ao;
    acd_data.credentialIdLength_be = ad->acd().credentialidlength_be();
    memcpy(ad_p, &acd_data.credentialIdLength_be, tmpLen);
    ad_buf_left -= tmpLen;
    ad_p += tmpLen;
 
 #ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Updated ad_buf_left: %lu\n", ad_buf_left);
#endif

    // variable
    tmpLen = ad->acd().credentialid().length();
#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("calculated credentialid length: %lu (should be 16 atm?)\n", tmpLen);
#endif
    // needs improvements!
    if (tmpLen != __builtin_bswap16(acd_data.credentialIdLength_be) ||
        tmpLen > ad_buf_left) goto err_ao;
    //ad->acd().credentialid().copy(acd_data.credentialId, tmpLen);
    memcpy(ad_p, ad->acd().credentialid().data(), tmpLen);
    ad_buf_left -= tmpLen;
    ad_p += tmpLen;

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Updated ad_buf_left: %lu\n", ad_buf_left);
#endif

    tmpLen = ad->acd().credentialpublickey().length();
    if (tmpLen > ad_buf_left) goto err_ao;
    memcpy(ad_p, ad->acd().credentialpublickey().data(), tmpLen);
    ad_buf_left -= tmpLen;
    ad_p += tmpLen;

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Updated ad_buf_left: %lu\n", ad_buf_left);
#endif

    // check buffer size has matched
    if (ad_buf_left != 0) {
        printf("AD buffer calculated as too big!\n");
        goto err_ao;
    }

    // "authData" -> bytes (TODO: move to end?)
    if (CborNoError != cbor_encode_text_stringz(&mapEncoder, "authData") ||
        CborNoError != cbor_encode_byte_string(&mapEncoder, ad_buffer, ad_buf_len)) {
            goto err_ao;
    }

    // "fmt" -> text (currently only for None type)
    if (CborNoError != cbor_encode_text_stringz(&mapEncoder, "fmt") ||
        CborNoError != cbor_encode_text_stringz(&mapEncoder, "none")) {
            goto err_ao;
    }

    // "attStmt" -> emptyMap (only for None type)
    if (CborNoError != cbor_encode_text_stringz(&mapEncoder, "attStmt") ||
        CborNoError != cbor_encoder_create_map(&mapEncoder, &nestedMapEncoder, 0)) {
            goto err_ao;
        }
    if (CborNoError != cbor_encoder_close_container(&mapEncoder, &nestedMapEncoder)) {
        goto err_ao;
    }

#if 0 // signing demo for (self-)attestation
    if (!(md_ctx = EVP_MD_CTX_create())) goto err_login;
    if(1 != EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, ctx->fido_ctx->fido_key)) goto err_login;

    if(1 != EVP_DigestSignUpdate(md_ctx, ctx->fido_ctx->login_challenge, ctx->fido_ctx->chllng_len)) goto err_login;

    // get length of signature and allocate resp. buffer
    if(1 != EVP_DigestSignFinal(md_ctx, NULL, &sig_len)) goto err_login;

    ch_signature = (uint8_t *)OPENSSL_malloc(sizeof(unsigned char) * (sig_len));
    if(!ch_signature) goto err_login;

    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(md_ctx, ch_signature, &sig_len)) goto err_login;

    ch_sgn_str = std::string((char *)ch_signature, sig_len);
    login_reply->set_signed_challenge(ch_sgn_str);
#endif

    if(CborNoError != cbor_encoder_close_container(&encoder, &mapEncoder)) {
        goto err_ao;
    }

    // Note: seems to copy from buf, so buf can be free'd from stack
    result_len = cbor_encoder_get_buffer_size(&encoder, buf);
    corse_pkey = new std::string((char *)buf, result_len);

err_ao:
    if (ad_buffer) free(ad_buffer);
    return corse_pkey;
}


// Currently we only support ES256 and assume an EC key
static std::string *FEIDO_FIDO_corse_encode_publickey(FEIDO_FIDO_CTX *ctx) {
    if (!ctx || !ctx->fido_key) return NULL;
    if (ctx->algorithm_id != -7) {
        printf("Error: given WebAuthn algorithm ID %d, but we only support -7 (ES256)\n",
            ctx->algorithm_id);
        return NULL;
    }
    if (EVP_PKEY_id(ctx->fido_key) != EVP_PKEY_EC) {
        printf("Error: currently only EC FIDO keys are supported\n");
        return NULL;
    }

    size_t result_len = 0;
    std::string *corse_pkey = NULL;

    uint8_t buf[384]; // TODO: what size? (X,Y are already 2x32 Bytes)
    CborEncoder encoder, mapEncoder;

    /* Prepare EC X and Y hex byte strings */

    EC_KEY *ec_key = NULL;
    const EC_POINT *ec_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    char *x_hex = NULL, *y_hex = NULL;
    unsigned char *x_bin = NULL, *y_bin = NULL;

    ec_key = EVP_PKEY_get0_EC_KEY(ctx->fido_key);
    if (!ec_key) goto err_corse;
    ec_point = EC_KEY_get0_public_key(ec_key);
    if (!ec_point) goto err_corse;

    x = BN_new();
    y = BN_new();
    if (!x || !y) goto err_corse;

    if (!EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec_key), ec_point, x, y, NULL)) goto err_corse;
#ifdef FEIDO_FIDO_HNDL_DEBUG
    x_hex = BN_bn2hex(x);
    y_hex = BN_bn2hex(y);
    if (!x_hex || !y_hex) goto err_corse;
    if (strlen(x_hex) != 64) {
        printf("Expected X hex len 64 (== 32 Byte as hex encoding), got: %lu\n", strlen(x_hex));
        //assert(false);
        //goto err_corse;
    }
    if (strlen(y_hex) != 64) {
        printf("Expected Y hex len 64 (== 32 Byte as hex encoding), got: %lu\n", strlen(y_hex));
        //assert(false);
        //goto err_corse;
    }
#endif

    x_bin = (unsigned char *)malloc(BN_num_bytes(x));
    y_bin = (unsigned char *)malloc(BN_num_bytes(y));
    if (!x_bin || !y_bin) {
        printf("OOM\n");
        goto err_corse;
    }

    assert(BN_num_bytes(x) == 32);
    assert(BN_num_bytes(y) == 32);

    if (BN_bn2bin(x, x_bin) <= 0) {
        printf("BN_bn2bin error\n");
        goto err_corse;
    }
    if (BN_bn2bin(y, y_bin) <= 0) {
        printf("BN_bn2bin error\n");
        goto err_corse;
    }

    /* COSE_Key --> instance of CBOR map */
    // see: https://www.w3.org/TR/webauthn-2/#sctn-encoded-credPubKey-examples
    // see: https://datatracker.ietf.org/doc/html/rfc8152#section-7

    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    // 5 entries
    if(CborNoError != cbor_encoder_create_map(&encoder, &mapEncoder, 5)) goto err_corse;

    // kty: EC2 key type
    if(CborNoError != cbor_encode_int(&mapEncoder, 1) ||
        CborNoError != cbor_encode_int(&mapEncoder, 2)) goto err_corse;

    // alg: E256
    if(CborNoError != cbor_encode_int(&mapEncoder, 3) ||
        CborNoError != cbor_encode_int(&mapEncoder, -7)) goto err_corse;

    // crv: P-256
    if(CborNoError != cbor_encode_int(&mapEncoder, -1) ||
        CborNoError != cbor_encode_int(&mapEncoder, 1)) goto err_corse;

    // EC x
    if(CborNoError != cbor_encode_int(&mapEncoder, -2) ||
        CborNoError != cbor_encode_byte_string(&mapEncoder, x_bin, BN_num_bytes(x)))
        goto err_corse;

    // EC y
    if(CborNoError != cbor_encode_int(&mapEncoder, -3) ||
        CborNoError != cbor_encode_byte_string(&mapEncoder, y_bin, BN_num_bytes(y))) {
        goto err_corse;
    }

    if(CborNoError != cbor_encoder_close_container(&encoder, &mapEncoder)) {
        goto err_corse;
    }

    // Note: seems to copy from buf, so buf can be free'd from stack
    result_len = cbor_encoder_get_buffer_size(&encoder, buf);
    corse_pkey = new std::string((char *)buf, result_len);

err_corse:
    // TODO: clean/close encoders?
    if (y_hex) OPENSSL_free(y_hex);
    if (x_hex) OPENSSL_free(x_hex);
    if (y) BN_free(y);
    if (x) BN_free(x);
    if (x_bin) free(x_bin);
    if (y_bin) free(y_bin);
    return corse_pkey;
}

static const char fix_aaguid[16] = {0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const char fix_credid[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static fido_sgx::attestedCredentialData* FEIDO_FIDO_craft_attestedCredentialData(FEIDO_FIDO_CTX *ctx) {
    auto acd = new fido_sgx::attestedCredentialData();
    if (!acd) {
        printf("acd OOM\n");
        return NULL;
    }
    acd->set_allocated_aaguid(new std::string(fix_aaguid, sizeof(fix_aaguid)));

    // assumes host order is LittleEndian
    uint16_t credIDlen = sizeof(fix_credid);
    uint16_t credIDlen_be = __builtin_bswap16(credIDlen);
    acd->set_credentialidlength_be(credIDlen_be);
#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("credIDlen: %lu, credIDlen_be: %lu\n", credIDlen, credIDlen_be);
#endif

    acd->set_allocated_credentialid(new std::string(fix_credid, credIDlen));

    auto corse_pkey = FEIDO_FIDO_corse_encode_publickey(ctx);
    if (!corse_pkey) {
        printf("Failed encoding public key\n");
        delete acd;
        return NULL;
    }
    acd->set_allocated_credentialpublickey(corse_pkey);

    return acd;
}


static fido_sgx::AuthenticatorData* FEIDO_FIDO_craft_authenticatorData(FEIDO_FIDO_CTX *ctx, fido_sgx::attestedCredentialData *acd) {
    auto ad = new fido_sgx::AuthenticatorData();

    // TODO: error handling!
    const int HASH_SIZE = EVP_MD_size(EVP_sha256());
    auto rpidHash = (unsigned char *)malloc(HASH_SIZE);
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    EVP_DigestInit(md_ctx, EVP_sha256());
    EVP_DigestUpdate(md_ctx, ctx->service_name, strlen(ctx->service_name));
    EVP_DigestFinal(md_ctx, rpidHash, NULL);
    auto rpidHash_str = new std::string((char *)rpidHash, HASH_SIZE);

    ad->set_allocated_rpidhash(rpidHash_str);
    
    uint8_t ad_flags = 0;
    ad_flags |= 0x1; // bit 0: user present

    // optional
    if (acd) {
        ad_flags |= 0x40; // bit 6 (acd included)
        ad->set_allocated_acd(acd);
    } else {
        ad->clear_acd();
        assert(!ad->has_acd());
    }

    ad->set_flags(ad_flags);
    ad->set_signcount_be(0); // unsupported: set constant to 0
    return ad;
}

/* AssertionSignature := Sign (credPrivK, AD || clientDataHash), ||: concat */
static std::string *FEIDO_FIDO_create_signed_assertion(FEIDO_FIDO_CTX *ctx, fido_sgx::AuthenticatorData *ad) {
    // ES256, i.e., ECDSA with SHA256
    if (ctx->algorithm_id != -7) {
        printf("Unsupported algorithm ID %d (currently only -7 supported, i.e., ES256)\n", ctx->algorithm_id);
        return NULL;
    }

#ifdef FEIDO_FIDO_HNDL_DEBUG
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(ctx->fido_key);
    if (!ec) {
        printf("Error: why is the FIDO key no EC key?\n");
        assert(false);
    }

    const EC_GROUP *g = EC_KEY_get0_group(ec);
    const EC_POINT *p = EC_KEY_get0_public_key(ec);
    
    int curve_nid = EC_GROUP_get_curve_name(g);
    printf("Curve: %s\n", OBJ_nid2sn(curve_nid));

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    assert(x && y);

    if (!EC_POINT_get_affine_coordinates(g, p, x, y, NULL)) assert(false);

    printf("X coordinate (hex):  %s\n", BN_bn2hex(x));
    printf("Y coordinate (hex):  %s\n", BN_bn2hex(y));

    BN_free(x);
    BN_free(y);
#endif

    std::string *ret_sign = NULL;

    EVP_MD_CTX *md_ctx = NULL;
    size_t sig_len;
    uint8_t *ch_signature = NULL;

    size_t concat_buf_len = 0;
    uint8_t *concat_buf = NULL;

    /* Prepare AD data */
    FIDO_AD ad_data;
    ad_data.flags = ad->flags();
    ad_data.signCount_be = ad->signcount_be();
    size_t hashLen = sizeof(ad_data.rpIdHash);
    if (hashLen != ad->rpidhash().length()) goto err_asssign;
    memcpy(ad_data.rpIdHash, ad->rpidhash().data(), hashLen);

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("sizeof(ad_data): %lu\n", sizeof(ad_data));
    printf("ad_data.flags: %x\n", ad_data.flags);
    printf("sizeof(ctx->cli_data_hash): %lu\n", sizeof(ctx->cli_data_hash));

    printf("\nAD as it flows into the Sign function:  ");
    for (int i=0; i<sizeof(ad_data); i++) {
        printf("%x ", ((uint8_t *)&ad_data)[i]);
    }
    printf("\n");

    printf("CliDataHash as it follows AD into the Sign function:  ");
    for (int i=0; i<sizeof(ctx->cli_data_hash); i++) {
        printf("%x ", ctx->cli_data_hash[i]);
    }
    printf("\n");
#endif

    /* Hash-Sign (atm: ECDSA-SHA256) AD||cliDdataHash */
    if (!(md_ctx = EVP_MD_CTX_create())) goto err_asssign;
    if(1 != EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, ctx->fido_key)) goto err_asssign;

    concat_buf_len = sizeof(ad_data) + sizeof(ctx->cli_data_hash);
    concat_buf = (uint8_t *) malloc(concat_buf_len);
    if (!concat_buf) goto err_asssign;
    memcpy(concat_buf, &ad_data, sizeof(ad_data));
    memcpy(concat_buf + sizeof(ad_data), ctx->cli_data_hash, sizeof(ctx->cli_data_hash));

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("\nConcat buffer == input to Sign function:  ");
    for (int i=0; i<concat_buf_len; i++) {
        printf("%x ", concat_buf[i]);
    }
    printf("\n");
#endif

    if(1 != EVP_DigestSignUpdate(md_ctx, concat_buf, concat_buf_len)) goto err_asssign;

    // get length of signature and allocate resp. buffer
    if(1 != EVP_DigestSignFinal(md_ctx, NULL, &sig_len)) goto err_asssign;

    ch_signature = (uint8_t *)OPENSSL_malloc(sizeof(unsigned char) * (sig_len));
    if(!ch_signature) goto err_asssign;

    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(md_ctx, ch_signature, &sig_len)) goto err_asssign;
    
    // TODO: does it copy, or take ownership?
    ret_sign = new std::string((char *)ch_signature, sig_len);

#ifdef FEIDO_FIDO_HNDL_DEBUG
    printf("Resulting Signature:  ");
    for (int i=0; i<ret_sign->length(); i++) {
        printf("%x ", ret_sign->data()[i]);
    }
    printf("\n\n");
#endif

err_asssign:
    if (concat_buf) free(concat_buf);
    // TODO: not free ch_signature if ret_sign != NULL ?
    if (ch_signature) OPENSSL_free(ch_signature);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);

    return ret_sign;
}


bool FEIDO_FIDO_derive_fido_keys(FEIDO_FIDO_CTX *ctx) {
    if (!ctx) return NULL;
    if (ctx->fido_key) {
        printf("FIDO key already set\n");
        return false;
    }

    KDF_INFO kdf_in {
        .service_name = ctx->service_name,
        .personal_data = ctx->personal_data,
    };
    ctx->fido_key = feido_derive_ecc_key_pair(kdf_in);
    return (ctx->fido_key != NULL);
}


bool FEIDO_FIDO_register(FEIDO_CTX *ctx) {
    if (!ctx) return false;
    if (!ctx->fido_ctx || !ctx->fido_ctx->fido_key || ctx->state != FEIDO_FIDO_REGISTER) {
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }

    uint8_t io_buf[384];
    size_t io_blen;

    fido_sgx::FidoRegisterReply *register_reply = NULL;
    fido_sgx::FidoResponse fd_resp;

    fido_sgx::attestedCredentialData *acd = NULL;
    fido_sgx::AuthenticatorData *ad = NULL;

    std::string *cbor_ao = NULL; // attestation object

    acd = FEIDO_FIDO_craft_attestedCredentialData(ctx->fido_ctx);
    if (!acd) {
        printf("Failed crafting ACD object\n");
        goto err_register;
    }

    ad = FEIDO_FIDO_craft_authenticatorData(ctx->fido_ctx, acd);
    if (!ad) {
        printf("Failed crafting AD object with built ACD object\n");
        goto err_register;
    }

    cbor_ao = FEIDO_FIDO_craft_attestationObject(ctx->fido_ctx, ad, ATT_NONE);
    if (!cbor_ao) {
        printf("Failed crafting AttestationObject\n");
        goto err_register;
    }


    /* Finalize Response and Send */
    register_reply = new fido_sgx::FidoRegisterReply();
    if (!register_reply) goto err_register;

    register_reply->set_allocated_attestationobject(cbor_ao);

    // TODO: only temporary (client should parse this out of the ACD)
    register_reply->set_allocated_credentialid(new std::string(fix_credid, sizeof(fix_credid)));

    fd_resp.set_allocated_register_(register_reply);

   // Serialize and send to client
    if (!fd_resp.SerializeToArray(io_buf, sizeof(io_buf))) {
        printf("Failed serializing FidoRegister Response (too small iobuf?)\n");
        // messages already stacked, so delete would cause double free
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }
    io_blen = fd_resp.ByteSizeLong();
    if (FEIDO_send_cli_message(ctx, ctx->cli_con.cli_ssl, io_buf, io_blen) <= 0) {
        // messages already stacked, so delete would cause double free
        return false;
    }

    ctx->state = FEIDO_DONE;
    return true;

err_register:
    // cleanup: must be careful regarding 'set_allocated_*()' calls
    if (register_reply) delete register_reply;
    else {
        if (cbor_ao) delete cbor_ao;
        if (ad) delete ad;
        else if (acd) delete acd;
    }

    ctx->state = FEIDO_DO_SHUTDOWN;
    return false;
}


bool FEIDO_FIDO_login(FEIDO_CTX *ctx) {
    if (!ctx) return false;
    if (!ctx->fido_ctx || !ctx->fido_ctx->fido_key || ctx->state != FEIDO_FIDO_LOGIN) {
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }    

    uint8_t io_buf[384];
    size_t io_blen;

    fido_sgx::FidoLoginReply *login_reply = NULL;
    fido_sgx::FidoResponse fd_resp;

    fido_sgx::AuthenticatorData *ad = NULL;
    std::string *assertion_signature = NULL;

    ad = FEIDO_FIDO_craft_authenticatorData(ctx->fido_ctx, NULL);
    if (!ad) goto err_login;

    assertion_signature = FEIDO_FIDO_create_signed_assertion(ctx->fido_ctx, ad);
    if (!assertion_signature) goto err_login;

    /* Finalize Response and Send */
    login_reply = new fido_sgx::FidoLoginReply();
    if (!login_reply) goto err_login;

    login_reply->set_allocated_ad(ad);
    login_reply->set_allocated_assertionsignature(assertion_signature);

    // TODO: only temporary?
    login_reply->set_allocated_credentialid(new std::string(fix_credid, sizeof(fix_credid)));

    fd_resp.set_allocated_login(login_reply);

    // Serialize and send to client
    if (!fd_resp.SerializeToArray(io_buf, sizeof(io_buf))) {
        printf("Failed serializing FidoLogin Response (too small iobuf?)\n");
        // messages already stacked, so delete would cause double free
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }
    io_blen = fd_resp.ByteSizeLong();
    if (FEIDO_send_cli_message(ctx, ctx->cli_con.cli_ssl, io_buf, io_blen) <= 0) {
        // messages already stacked, so delete would cause double free
        return false;
    }

    ctx->state = FEIDO_DONE;
    return true;

err_login:
    // cleanup: must be careful regarding 'set_allocated_*()' calls
    if (login_reply) delete login_reply;
    else {
        if (assertion_signature) delete assertion_signature;
        if (ad) delete ad;
    }

    ctx->state = FEIDO_DO_SHUTDOWN;
    return false;
}