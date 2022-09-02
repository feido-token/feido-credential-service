#include "feido_revocation.h"

#include "feido-database.pb.h"

#include "feido_ctx.h"

#include "Enclave.h" // printf

extern "C" {
    #include "Enclave_t.h"
}

#ifndef ICHECKIT_SVC_ADDRESS
#define ICHECKIT_SVC_ADDRESS NULL
#endif

#ifndef ICHECKIT_SVC_PORT
#define ICHECKIT_SVC_PORT -1
#endif

FEIDO_REVOKE_CTX feido_revoke_ctx = {

#if QUERY_ICHECKIT_SERVICE
    .feido_query_eid_db = 1,
#else
    .feido_query_eid_db = 0,
#endif

    .ip4_address = ICHECKIT_SVC_ADDRESS,
    .port = ICHECKIT_SVC_PORT,

    .db_ssl_ctx = NULL,
};

typedef struct revokation_session {
    SSL *db_tls;
} FEIDO_REVOKE_SESS;

static bool setup_db_ssl_context(FEIDO_REVOKE_CTX *rev_ctx);
static bool free_db_ssl_context(FEIDO_REVOKE_CTX *rev_ctx);

static bool connect_to_eid_database(FEIDO_REVOKE_CTX *ctx, FEIDO_REVOKE_SESS *rev_sess);
static void close_eid_connection(FEIDO_REVOKE_SESS *rev_sess);

static bool query_eid_database(FEIDO_CTX *ctx, FEIDO_REVOKE_SESS *rev_sess);
static bool receive_db_response(FEIDO_CTX *ctx, FEIDO_REVOKE_SESS *rev_sess, bool *is_revoked);


bool setup_db_ssl_context(FEIDO_REVOKE_CTX *rev_ctx) {
    if (!rev_ctx) return false;
    if (rev_ctx->db_ssl_ctx) return true; // nothing to do?
    rev_ctx->db_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!rev_ctx->db_ssl_ctx) return false;

    // TODO: for testing: disable server certificate verification
    // this is insecure; set accepted datbase service certificate for server
    // verification during the TLS handshake
    SSL_CTX_set_verify(rev_ctx->db_ssl_ctx, SSL_VERIFY_NONE, nullptr);
    return true;
}

// TODO: when to call? (incorporate into global server status)
bool free_db_ssl_context(FEIDO_REVOKE_CTX *rev_ctx) {
    if (!rev_ctx->db_ssl_ctx) return true; // nothing to do?
    SSL_CTX_free(rev_ctx->db_ssl_ctx);
    rev_ctx->db_ssl_ctx = NULL;
    return true;
}

bool FEIDO_check_eid_revocation_status(FEIDO_CTX *ctx) {
    if (!ctx) {
        printf("no ctx\n");
        return false;
    }
    if (ctx->state != FEIDO_REVOCATION_LOOKUP) {
        ctx->state = FEIDO_ERROR;
        printf("wrong state\n");
        return false;
    }

    // (0) set up SSL context if required
    if (!feido_revoke_ctx.db_ssl_ctx && !setup_db_ssl_context(&feido_revoke_ctx)) {
        printf("failed setting up ssl context\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }

    FEIDO_REVOKE_SESS rev_sess;


    // (1) connect to eID database
    if (!connect_to_eid_database(&feido_revoke_ctx, &rev_sess)) {
        printf("failed TLS connection to eID database service\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }


    // (2) send protobuf query message
    if (!query_eid_database(ctx, &rev_sess)) {
        printf("failed to query eID database service\n");
        goto db_error;
    }


    // (3) receive protobuf response message
    bool eid_is_revoked;
    if (!receive_db_response(ctx, &rev_sess, &eid_is_revoked)) {
        printf("failed to receive eID service response\n");
        goto db_error;
    }


    // (4) cleanup
    close_eid_connection(&rev_sess);


    // (5) continue (true) if not revoked
    // TODO: make errors and revoked status distinguishable
    return !eid_is_revoked;

db_error:
    close_eid_connection(&rev_sess);
    ctx->state = FEIDO_DO_SHUTDOWN;
    return false;
}



bool connect_to_eid_database(FEIDO_REVOKE_CTX *ctx, FEIDO_REVOKE_SESS *rev_sess) {
    if (!ctx || !rev_sess) return false;

    int sock_fd {-1};
    SSL *tmp_ssl;

    // (1) OCALL for setting up an untrusted TCP connection to the DB server
    // based on SENG-SDK
    sgx_status_t status = ocall_setup_db_conn(&sock_fd, ctx->port, ctx->ip4_address);
    if (status != SGX_SUCCESS || sock_fd < 0) {
        printf("Creating TCP connection to revocation db service failed\n");
        return false;
    }

    // (2) Create SSL session object and associate it with the TCP socket
    tmp_ssl = SSL_new(feido_revoke_ctx.db_ssl_ctx);
    if (tmp_ssl == nullptr) {
        printf("SSL session object creation failed\n");
        return false;
    }
    SSL_set_mode(tmp_ssl, SSL_MODE_AUTO_RETRY);

    if (!SSL_set_fd(tmp_ssl, sock_fd)) {
        SSL_free(tmp_ssl);
        return false;
    }

    // (3) Perform the TLS handshake on the TCP connection
    int ret = SSL_connect(tmp_ssl);
    if (ret <= 0) {
        auto ssl_err = SSL_get_error(tmp_ssl, ret);
        printf ("Handshake failed with SSL Error: %d\n", ssl_err);
        SSL_shutdown(tmp_ssl);
        SSL_free(tmp_ssl);
        return false;
    }

    // finalize
    rev_sess->db_tls = tmp_ssl;
    return true;
}

void close_eid_connection(FEIDO_REVOKE_SESS *rev_sess) {
    if (!rev_sess || !rev_sess->db_tls) return;
    int sock_fd = SSL_get_fd(rev_sess->db_tls);

    SSL_shutdown(rev_sess->db_tls); // todo: calling once might not be enough
    SSL_free(rev_sess->db_tls);

    sgx_status_t status = ocall_close_db_conn(sock_fd);
    (void)status;
}


bool query_eid_database(FEIDO_CTX *ctx, FEIDO_REVOKE_SESS *rev_sess) {
    if (!ctx || !rev_sess) return false;

    uint8_t io_buf[128];
    feido_db::ICheckitQuery query_msg;

    FORM_DG1 *dg1_data = ctx->fido_ctx->personal_data;

    switch (dg1_data->format)
    {
    case TD1: {
        const struct dg1_td1 *data = dg1_data->td_data.td1_data;
        // TODO: protobuf should not free the buffers as we do not use set_allocated
        query_msg.set_traveldocumentnumber(data->document_number, sizeof(data->document_number));
        query_msg.set_countryofissuance(data->issuing_state_org, sizeof(data->issuing_state_org));
        query_msg.set_documenttype(data->document_code, sizeof(data->document_code));
        break;
    }

    case TD2: {
        const struct dg1_td2 *data = dg1_data->td_data.td2_data;
        // TODO: protobuf should not free the buffers as we do not use set_allocated
        query_msg.set_traveldocumentnumber(data->document_number, sizeof(data->document_number));
        query_msg.set_countryofissuance(data->issuing_state_org, sizeof(data->issuing_state_org));
        query_msg.set_documenttype(data->document_code, sizeof(data->document_code));
        break;
    }

    case TD3: {
        const struct dg1_td3 *data = dg1_data->td_data.td3_data;
        // TODO: protobuf should not free the buffers as we do not use set_allocated
        query_msg.set_traveldocumentnumber(data->document_number, sizeof(data->document_number));
        query_msg.set_countryofissuance(data->issuing_state_org, sizeof(data->issuing_state_org));
        query_msg.set_documenttype(data->document_code, sizeof(data->document_code));
        break;
    }

    default:
        return false;
    }

    if (!query_msg.SerializeToArray(io_buf, sizeof(io_buf))) {
        printf("Failed serializing ICheckitQuery msg\n");
        return false;
    }

    if (FEIDO_send_cli_message(ctx, rev_sess->db_tls, io_buf, query_msg.ByteSizeLong()) <= 0) {
        printf("Failed sending ICheckitQuery message\n");
        return false;
    }

    return true;
}

bool receive_db_response(FEIDO_CTX *ctx, FEIDO_REVOKE_SESS *rev_sess, bool *is_revoked) {
    if (!ctx || !rev_sess) return false;

    uint8_t recv_buf[128];
    int ndata;
    feido_db::ICheckitResponse response;

    printf("Wait for a eID Revocation Lookup Query message from Client\n");
    ndata = FEIDO_receive_cli_message(ctx, rev_sess->db_tls, recv_buf, sizeof(recv_buf));
    if (ndata <= 0) {
        printf("failed to receive database service reply\n");
        return false;
    }

    if (!response.ParseFromArray(recv_buf, ndata)) {
        printf("Protobuf Error: Failed parsing ICheckitResponse message\n");
        return false;
    }
    if (response.isdbhit()) {
        printf("eID has been revoked in the database service\n");
    }

    *is_revoked = response.isdbhit();
    return true;
}