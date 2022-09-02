#include "feido_ca_handling.h"

#include "fido_sgx.pb.h"

#include <fido_sgx_sod_dg.h>
#include <fido_sgx_ca.h>

#include "Enclave.h"

#include <eac/eac.h>

// for secure messaging GetChallenge
#include <vector>
#include <cstddef>
extern "C" {
    #include <eac_util.h>
    #include <misc.h>
}

#include "Enclave_debug.h"

#ifdef FEIDO_GLOBAL_DEBUG
#define FEIDO_CA_DEBUG
#endif

static std::string *FEIDO_craft_get_challenge(FEIDO_CTX *ctx);
static bool FEIDO_check_response_mac(FEIDO_CTX *ctx, const std::string &msg);
//

static const DG *EPASS_get_dg(EPASS_CTX *ctx, DG_Type type);

static bool FEIDO_perform_ca_steps(FEIDO_CTX *ctx, fido_sgx::CAInit &ca_msg);
static bool FEIDO_check_ca_channel(FEIDO_CTX *ctx);


const DG *EPASS_get_dg(EPASS_CTX *ctx, DG_Type type) {
    if (!ctx || !ctx->dgs) return NULL;
    for (unsigned int i=0; i<ctx->dg_num; i++) {
        const DG *tmp = ctx->dgs[i];
        if (tmp && tmp->type == type) return tmp;
    }
    return NULL;
}

bool FEIDO_handle_dgs_and_ca_protocol(FEIDO_CTX *ctx) {
    if (!ctx) {
        printf("no ctx\n");
        return false;
    }
    if (ctx->state != FEIDO_WAIT_CA_INIT) {
        ctx->state = FEIDO_ERROR;
        printf("wrong state\n");
        return false;
    }

    uint8_t io_buf[3072]; // CAInit showed 2741 Bytes in log
    int ndata;

    /* (1) Receive CA Init message */
    ndata = FEIDO_receive_cli_message(ctx, ctx->cli_con.cli_ssl, io_buf, sizeof(io_buf));
    if (ndata <= 0) {
        printf("receive returned: %d\n", ndata);
        return false;
    }

    fido_sgx::CAInit ca_msg;
    if (!ca_msg.ParseFromArray(io_buf, ndata)) {
        printf("Protobuf Error: Parsing CAInit message failed\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }

    /* (2) Parse DGs and CA-required data */

    // DGs
    int parsed_dgs = 0;
    for (auto const& dg_entry : ca_msg.data_groups()) {
        int32_t dg_num = dg_entry.first;
        fido_sgx::CAInit_DataGroup const &dg = dg_entry.second;

        auto new_dg = (DG *)malloc(sizeof(DG));
        if (!new_dg) {
            printf("Failed allocating DG (OOM)\n");
            ctx->state = FEIDO_DO_SHUTDOWN;
            return false;
        }

        /* TODO: maybe putting string into DG and using dg.release_group_data()
         *      would be an option that avoids extra copying -- but I think the
         *      code where th DG is free'd is currently C, i.e., there is no
         *      delete to free the string afterwards */
        new_dg->raw_len = dg.group_data().length();
        new_dg->raw_data = (unsigned char *)malloc(new_dg->raw_len);
        if (!new_dg->raw_data) {
            printf("Failed allocating DG data buffer (OOM)\n");
            free(new_dg);
            ctx->state = FEIDO_DO_SHUTDOWN;
            return false;
        }
        memcpy(new_dg->raw_data, dg.group_data().data(), new_dg->raw_len);

        new_dg->type = static_cast<DG_Type>(dg_num);
        /* Strip <tag>|<length> of Java library
         *
         * problem: length is variable size depending on data length;
         * if >= 0x80, it is 1B + (<1.Byte> & ~0x80) Bytes
         * 
         * tag was always 1B so far
         */

#define DG1_TAG 0x61
#define DG1_MRZ_TAG 0x5F1F

        auto data_ptr = new_dg->raw_data; //(unsigned char *)dg.group_data().data();
        bool dg1_extra_decoding = (new_dg->type == DG1);
        if (dg1_extra_decoding) {
            // sanity check
            if (*data_ptr != DG1_TAG) {
                printf("Error: parsing DG1 tag, but the Java lib DG1 tag is wrong\n");
                ctx->state = FEIDO_DO_SHUTDOWN;
                free(new_dg->raw_data);
                free(new_dg);
                return false;
            }
        }
        data_ptr += 1; // skip tag (todo: could check if it is in 0x61 - 0x6E)

        size_t data_len = 0;

        if (*data_ptr >= 0x80) {
            unsigned int extra_bytes = *data_ptr ^ 0x80;
#ifdef FEIDO_CA_DEBUG
            printf("length extra Bytes: %u\n", extra_bytes);
#endif
            data_ptr += 1;
            for (int i=0; i<extra_bytes; i++) {
                data_len = (data_len << 8) | *data_ptr;
                data_ptr++;
            }
        } else {
            data_len = *data_ptr;
            data_ptr += 1; // skip small length
            if (data_len >= dg.group_data().length()) {
                printf("Error: wrong size calculation of DG\n");
                printf("Calculated: %u, but whole buffer is only: %u\n",
                    data_len, dg.group_data().length());
                ctx->state = FEIDO_DO_SHUTDOWN;
                free(new_dg->raw_data);
                free(new_dg);
                return false;
            } 
        }

        /* required because Java library encodes DGs:
         * <tag>|<dg-len>|<dg>,
         * but extra encodes DG1:
         * <tag>|<tagged-len>|<mrz-tag>|<dg-len>|<dg>
         */
        if (dg1_extra_decoding) {
#ifdef FEIDO_CA_DEBUG
            printf("Parsing DG1, need to strip Java lib's MRZ tag\n");
#endif
            if (*data_ptr != 0x5F && *(++data_ptr) != 0x1F) {
                printf("Invalid MRZ info tag\n");
                ctx->state = FEIDO_DO_SHUTDOWN;
                free(new_dg->raw_data);
                free(new_dg);
                return false;
            }
            data_ptr += 2;
            data_len = *data_ptr; // actual DG1/MRZ data length
            data_ptr += 1;
        }

        //
        new_dg->data = data_ptr;
        new_dg->len = data_len;

#ifdef FEIDO_CA_DEBUG
        printf("DG data pointer: %p, len: %lu\n", data_ptr, data_len);
#endif

        ctx->epass_ctx->dgs[parsed_dgs] = new_dg;
        parsed_dgs++;
        if (parsed_dgs >= MAX_DGS) break;
    }
    ctx->epass_ctx->dg_num = parsed_dgs;

    // DSO, currently includes (3) Passive Authentication (todo: move after CA?)
    if (!FIDO_SGX_parse_document_security_object((const unsigned char *)ca_msg.document_security_object().data(), ca_msg.document_security_object().length(), ctx->epass_ctx)) {
        printf("Failed parsing SOD (document security object)\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }
#ifdef FEIDO_CA_DEBUG
    printf ("Successfully parsed SOD\n");
#endif

    // DG14 (SecurityInfos)
    if (!FIDO_SGX_parse_dg14_ca_infos(ctx->epass_ctx, EPASS_get_dg(ctx->epass_ctx, DG14))) {
        printf("Failed parsing DG14 CA Infos\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }
#ifdef FEIDO_CA_DEBUG
    printf ("Successfully parsed DG14\n");

    printf("default ka_ctx->peer_pubkey: %p\n",
        ctx->epass_ctx->ca_ctx->ka_ctx->peer_pubkey);
    printf("default ca_ctx keyID: %d\n", ctx->epass_ctx->ca_ctx->id);
#endif

    // DG1 (Personal Data)
    ctx->fido_ctx->personal_data = FIDO_SGX_parse_dg1(ctx->epass_ctx, EPASS_get_dg(ctx->epass_ctx, DG1));
    if (!ctx->fido_ctx->personal_data) {
        printf("Failed parsing DG1 Personal Data\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }
#ifdef FEIDO_CA_DEBUG
    printf ("Successfully parsed DG1\n");

    FIDO_SGX_print_form_dg1(ctx->fido_ctx->personal_data);
#endif

    /* (4) Chip Authentication (todo: swap with PA?) */
    if (!FEIDO_perform_ca_steps(ctx, ca_msg)) {
        printf("CA Steps failed\n");
        return false;
    }
#ifdef FEIDO_CA_DEBUG
    printf("Successfully performed ChipAuthentication steps, now need to check if connection has been correctly established\n");
#endif

    /* (5) "Pseudo" Terminal Authentication request */
    if (!FEIDO_check_ca_channel(ctx)) {
        printf("CA Channel verification failed\n");
        return false;
    }
#ifdef FEIDO_CA_DEBUG
    printf("Successfully verified the CA connection for both peers\n");
#endif

    ctx->state = FEIDO_CA_DONE;
    return true;
}




bool FEIDO_perform_ca_steps(FEIDO_CTX *ctx, fido_sgx::CAInit &ca_msg) {
    if (!ctx) return false;
    if (!ctx->epass_ctx) {
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }

    // CA pubilc key of ePassport, and ephemeral one of enclave
    BUF_MEM *epass_ca_pubkey = NULL, *enc_ca_eph_pubkey = NULL;

    fido_sgx::CAInitReply ca_reply;
    uint8_t io_buf[128];
    ASN1_OBJECT *ca_oid = NULL;
    char oid_buf[80];

    // chooses the default-selected ePassport key (1st parsed from DG14)
    // TODO: keyID-based choice as alternative
    epass_ca_pubkey = CA_STEP1_get_epass_pubkey(ctx->epass_ctx);
    if (!epass_ca_pubkey) {
        printf("Failed to get CA public key from DG14 parsing\n");
        goto err_ca_steps;
    }
#ifdef FEIDO_CA_DEBUG
    printf("Got default-chosen ePassport CA public key\n");
#endif

    ctx->state = FEIDO_SEND_CA_EPHM_PKEY;
    enc_ca_eph_pubkey = CA_STEP2_generate_eph_keypair(ctx->epass_ctx);
    if (!enc_ca_eph_pubkey) goto err_ca_steps;
#ifdef FEIDO_CA_DEBUG
    printf("Generated ephemeral CA key pair of Enclave\n");
#endif

    /* Send CAInitReply message to client */
    // TODO: I think we don't need to free ca_oid, but I'm not 100% sure
    ca_oid = OBJ_nid2obj(ctx->epass_ctx->ca_ctx->protocol);
    OBJ_obj2txt(oid_buf, sizeof(oid_buf), ca_oid, 1); /* digit-dot form */

    ca_reply.set_ca_cipher_oid_txt(oid_buf);
    ca_reply.set_epass_key_id(ctx->epass_ctx->ca_ctx->id);
    ca_reply.set_ephm_enclave_public_key(enc_ca_eph_pubkey->data, enc_ca_eph_pubkey->length);

    if (!ca_reply.SerializeToArray(io_buf, sizeof(io_buf))) {
        printf("Failed serializing CAInitReply msg\n");
        goto err_ca_steps;
    }

    if (FEIDO_send_cli_message(ctx, ctx->cli_con.cli_ssl, io_buf, ca_reply.ByteSizeLong()) <= 0) {
        printf("Failed sending CAInitReply message\n");
        goto err_ca_steps;
    }

#ifdef FEIDO_CA_DEBUG
    printf("Sent CAInitReply message out to Client\n");
#endif
    /* */

    if (!CA_STEP4_compute_shared_secret(ctx->epass_ctx, epass_ca_pubkey)) {
        printf("Computing CA shared secret failed\n");
        goto err_ca_steps;
    }
#ifdef FEIDO_CA_DEBUG
    printf("Computed CA shared secret\n");
#endif

    if (-1 == CA_STEP6_derive_keys(ctx->epass_ctx)) {
        printf("Deriving CA connection keys failed\n");
        goto err_ca_steps;
    }
#ifdef FEIDO_CA_DEBUG
    printf("Derived CA communication keys\n");
#endif

    if (!EPASS_CTX_set_encryption_ctx(ctx->epass_ctx, EAC_ID_CA))
        goto err_ca_steps;

    BUF_MEM_clear_free(enc_ca_eph_pubkey);
    BUF_MEM_clear_free(epass_ca_pubkey);
    return true;

err_ca_steps:
    if (enc_ca_eph_pubkey) BUF_MEM_clear_free(enc_ca_eph_pubkey);
    if (epass_ca_pubkey) BUF_MEM_clear_free(epass_ca_pubkey);

    ctx->state = FEIDO_DO_SHUTDOWN;
    return false;
}


bool FEIDO_check_ca_channel(FEIDO_CTX *ctx) {
    if (!ctx) return false;
    uint8_t io_buf[128];
    int ndata;

    fido_sgx::AE_TAChallengeReq ta_req;
    fido_sgx::AE_TAChallengeResp ta_challenge;

    /* Craft + send TA command */
    ctx->state = FEIDO_SEND_CA_TA_INIT_CMD;

    EAC_set_ssc(ctx->epass_ctx, 1); // do NOT use 0, it is WRONG

    auto sm_cmd = FEIDO_craft_get_challenge(ctx);
    if (!sm_cmd) goto err_check_cachan;

    EAC_increment_ssc(ctx->epass_ctx); // important

    ta_req.set_allocated_msg_blob(sm_cmd);
    if (!ta_req.SerializeToArray(io_buf, sizeof(io_buf))) goto err_check_cachan;

#ifdef FEIDO_CA_DEBUG
    printf("Sending AE_TAChallengeReq message to Client\n");
#endif
    if (FEIDO_send_cli_message(ctx, ctx->cli_con.cli_ssl, io_buf, ta_req.ByteSizeLong()) <= 0) {
        return false;
    }



    /* Recv + check reponse message */
    ctx->state = FEIDO_WAIT_CA_TA_NONCE;

#ifdef FEIDO_CA_DEBUG
    printf("Trying to receive AE_TAChallengeResp message from Client\n");
#endif
    ndata = FEIDO_receive_cli_message(ctx, ctx->cli_con.cli_ssl, io_buf, sizeof(io_buf));
    if (ndata <= 0) return false;

    if (!ta_challenge.ParseFromArray(io_buf, ndata)) {
        printf("Protobuf Error: Parsing AE_TAChallengeResp message failed\n");
        goto err_check_cachan;
    }

    // SSC already incremented above
    if (!FEIDO_check_response_mac(ctx, ta_challenge.msg_blob())) {
        printf("Failed checking MAC of response ADPU\n");
        goto err_check_cachan;
    }

#ifdef FEIDO_CA_DEBUG
    printf("Successfully verified the ChipAuthentication channel between Enclave and ePassport\n");
#endif
    return true;

err_check_cachan:
    ctx->state = FEIDO_DO_SHUTDOWN;
    return false;
}


/* GetChallenge hacky crafting (secure messaging) */
struct apdu_header {
    unsigned char cla, ins, p1, p2;	/* CLA, INS, P1 and P2 bytes */
};

struct simple_apdu {
    struct apdu_header hdr;
	size_t le;			/* Le byte */
	//unsigned char mac[8];
};

// Important: you must set the SSC correctly before calling this API
std::string *FEIDO_craft_get_challenge(FEIDO_CTX *ctx) {
    if (!ctx || !ctx->epass_ctx) return NULL;

    std::string *ret_sm_msg = NULL;
    BUF_MEM *header = NULL, *hdr_pad = NULL;
    BUF_MEM *le_entry = NULL, *le_entry_pad = NULL;

    std::vector<unsigned char> sm_buf;

    // Plain GetChallenge command: 0x00 0x84 0x00 0x00 0x08
    struct simple_apdu apdu_cmd;
    apdu_cmd.hdr.cla = 0x00;
    apdu_cmd.hdr.ins = 0x84;
    apdu_cmd.hdr.p1 = 0x00;
    apdu_cmd.hdr.p2 = 0x00;

    apdu_cmd.le = 0x08;

    // ----------------------------------------------

    apdu_cmd.hdr.cla = 0x0C; // secure messaging


    /* Calculate the MAC (cf. Figure 4--6 in TR-03110 Part 3: Common Specifications) */

    BUF_MEM *mac_data = NULL;
    BUF_MEM *mac_signature = NULL;

    header = BUF_MEM_create(sizeof(apdu_cmd.hdr));
    if (!header) goto err_sm;
    header->data[0] = apdu_cmd.hdr.cla;
    header->data[1] = apdu_cmd.hdr.ins;
    header->data[2] = apdu_cmd.hdr.p1;
    header->data[3] = apdu_cmd.hdr.p2;

    // header
    hdr_pad = EAC_add_iso_pad(ctx->epass_ctx, header);
    if (!hdr_pad) goto err_sm;
    BUF_MEM_free(header); header = NULL;

    // Le
    le_entry = BUF_MEM_create(3);
    if (!le_entry) goto err_sm;
    le_entry->data[0] = 0x97; // tag
    le_entry->data[1] = 0x01; // len
    le_entry->data[2] = apdu_cmd.le;

    le_entry_pad = EAC_add_iso_pad(ctx->epass_ctx, le_entry);
    if (!le_entry_pad) goto err_sm;
    BUF_MEM_free(le_entry); le_entry = NULL;

    mac_data = BUF_MEM_create(hdr_pad->length + le_entry_pad->length);
    if (!mac_data) goto err_sm;
    memcpy(mac_data->data, hdr_pad->data, hdr_pad->length);
    memcpy(mac_data->data + hdr_pad->length, le_entry_pad->data, le_entry_pad->length);

    BUF_MEM_free(hdr_pad); hdr_pad = NULL;
    BUF_MEM_free(le_entry_pad); le_entry_pad = NULL;

    // Check that SSC is correct!

    mac_signature = EAC_authenticate(ctx->epass_ctx, mac_data);
    if (!mac_signature) goto err_sm;
    BUF_MEM_free(mac_data); mac_data = NULL;

    // ----------------------------------------------

    /* Wrap the command */
    sm_buf.push_back(apdu_cmd.hdr.cla);
    sm_buf.push_back(apdu_cmd.hdr.ins);
    sm_buf.push_back(apdu_cmd.hdr.p1);
    sm_buf.push_back(apdu_cmd.hdr.p2);

    // new Lc: 13B
    sm_buf.push_back(0x0D);

    // protected Le, 3 Bytes
    sm_buf.push_back(0x97); // tag
    sm_buf.push_back(0x01); // len
    sm_buf.push_back(apdu_cmd.le);

    // cryptographic checksum, 10 Bytes
    sm_buf.push_back(0x8E); // tag
    sm_buf.push_back(0x08); // len
    for (size_t i=0; i<mac_signature->length; i++) {
        sm_buf.push_back(mac_signature->data[i]);
    }

    // final 0 byte
    sm_buf.push_back(0x00);

    ret_sm_msg = new std::string((char *)sm_buf.data(), sm_buf.size());

err_sm:
    if(mac_signature) BUF_MEM_free(mac_signature);
    if(mac_data) BUF_MEM_free(mac_data);
    if(le_entry_pad) BUF_MEM_free(le_entry_pad);
    if(le_entry) BUF_MEM_free(le_entry);
    if(hdr_pad) BUF_MEM_free(hdr_pad);
    if(header) BUF_MEM_free(header);
    return ret_sm_msg;
}

// Important: must adapt SSC correctly before calling this API
bool FEIDO_check_response_mac(FEIDO_CTX *ctx, const std::string &msg) {
    if (!ctx || !ctx->epass_ctx || (msg.length() < 8)) return false;
    bool ret = false;
    BUF_MEM *data = NULL, *pad_data = NULL, *mac = NULL;

    /*
     * [0x87 <L> 0x01 <crypt>] [0x99 0x02 SW1(1B) SW2(1B)] [0x8E 0x08 <mac>] [SW1(1B) SW2(1B)]
     *
     * <mac> is over pad ( [0x87 <L> 0x01 <crypt>] [0x99 0x02 SW1(1B) SW2(1B)] )
     */
    size_t buf_len = 0;
    // TODO: had off-by-one regarding <L> (1 too big), so I think <L> includes
    //      the 0x01 Bytes plus the length of <crypt>
    buf_len += 2;
    buf_len += (uint8_t)msg.data()[1];
    buf_len += 4;
    if (buf_len > msg.length()) goto err_mac_check;

    data = BUF_MEM_create(buf_len);
    if (!data) goto err_mac_check;
    memcpy(data->data, msg.data(), buf_len);

    pad_data = EAC_add_iso_pad(ctx->epass_ctx, data);
    if (!pad_data) goto err_mac_check;

    if (((uint8_t)msg.data()[buf_len]) != 0x8E) {
        printf("MAC tag not at expected position\n");
        goto err_mac_check;
    }
    if (msg.data()[buf_len+1] != 0x08) {
        printf("Unexpected MAC length\n");
        goto err_mac_check;
    }

    mac = BUF_MEM_create(8);
    if (!mac) goto err_mac_check;
    memcpy(mac->data, (uint8_t *)&msg.data()[buf_len+2], 8);

    ret = (1 == EAC_verify_authentication(ctx->epass_ctx, pad_data, mac));
    if (!ret) printf("MAC verification failed\n");

err_mac_check:
    if (mac) BUF_MEM_free(mac);
    if (pad_data) BUF_MEM_free(pad_data);
    if (data) BUF_MEM_free(data);
    return ret;
}