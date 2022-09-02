#include "feido_ctx.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <eac/eac.h>

#include "Enclave.h" // printf

#include "fido_sgx.pb.h"

#include "feido_ca_handling.h"
#include "feido_fido_handling.h"

#include "Enclave_debug.h"

#include "eid-revoke/feido_revocation.h"

#ifdef FEIDO_GLOBAL_DEBUG
#define FEIDO_CTX_DEBUG
#endif

typedef enum { FEIDO_READ, FEIDO_WRITE } FEIDO_IO_OP;
static int FEIDO_do_cli_io(FEIDO_CTX *ctx, SSL *ssl_con, void *buf, size_t blen, FEIDO_IO_OP op);


FEIDO_CTX *FEIDO_create_context(void) {
    auto ctx = (FEIDO_CTX *)calloc(1, sizeof(FEIDO_CTX));
    if (!ctx) return NULL;
    assert (ctx->state == FEIDO_NO_CLI);

    ctx->fido_ctx = (FEIDO_FIDO_CTX *)calloc(1, sizeof(FEIDO_FIDO_CTX));
    if (!ctx->fido_ctx) goto error;

    ctx->epass_ctx = EPASS_CTX_new();
    if (!ctx->epass_ctx) goto error;

    return ctx;

error:
    if (ctx->fido_ctx) free(ctx->fido_ctx);
    if (ctx) free(ctx);
    return NULL;
}

void FEIDO_free_context(FEIDO_CTX *ctx) {
    if (!ctx) return;
    if (ctx->cli_con.cli_ssl) {
        SSL_free(ctx->cli_con.cli_ssl);
        ctx->cli_con.cli_ssl = NULL;
    }
    if (ctx->fido_ctx) {
        if (ctx->fido_ctx->fido_key) EVP_PKEY_free(ctx->fido_ctx->fido_key);
        if (ctx->fido_ctx->service_name) free(ctx->fido_ctx->service_name);
//        if (ctx->fido_ctx->login_challenge) free(ctx->fido_ctx->login_challenge);
        if (ctx->fido_ctx->personal_data) free(ctx->fido_ctx->personal_data);
        ctx->fido_ctx = NULL;
    }
    if (ctx->epass_ctx) {
        EPASS_CTX_clear_free(ctx->epass_ctx);
        ctx->epass_ctx = NULL;
    }
    ctx->state = FEIDO_ERROR;
    free (ctx);
}


bool FEIDO_setup_cli_con(FEIDO_CTX *ctx, SSL_CTX *srv_ctx, int sock_fd) {
    if (!ctx) return false;
    SSL *cli_ssl;
    if (!srv_ctx || ctx->state != FEIDO_NO_CLI) goto error;

    // SSL client context
    cli_ssl = SSL_new(ssl_srv_ctx);
    if (!cli_ssl) {
        printf("Failed SSL client context creation\n");
        goto error;
    }
    if (!SSL_set_fd(cli_ssl, sock_fd)) {
        SSL_free(cli_ssl);
        goto error;
    }
    // TLS establishment
    if (SSL_accept(cli_ssl) <= 0) {
        printf("SSL accept failed\n");
        SSL_shutdown(cli_ssl);
        SSL_free(cli_ssl);
        goto error;
    }
    // finalize
    ctx->cli_con.cli_ssl = cli_ssl;
    ctx->state = FEIDO_WAIT_CMD;
    return true;

error:
    ctx->state = FEIDO_ERROR;
    return false;
}

bool FEIDO_handle_cli_cmd(FEIDO_CTX *ctx) {
    if (!ctx) return false;
    if (ctx->state != FEIDO_WAIT_CMD) {
        ctx->state = FEIDO_ERROR;
        return false;
    }

    uint8_t recv_buf[128];
    int ndata;

    /* Receive FidoRequest Message */
    printf("Wait for a FidoRequest message from Client\n");
    ndata = FEIDO_receive_cli_message(ctx, ctx->cli_con.cli_ssl, recv_buf, sizeof(recv_buf));
    if (ndata <= 0) return false;

    fido_sgx::FidoRequest request;
    if (!request.ParseFromArray(recv_buf, ndata)) {
        printf("Protobuf Error: Failed parsing FidoRequest message (command)\n");
        ctx->state = FEIDO_DO_SHUTDOWN;
        return false;
    }

    switch (request.request_case())
    {
        case fido_sgx::FidoRequest::RequestCase::kRegister: {
            fido_sgx::FidoRegister reg = request.register_();
#ifdef FEIDO_CTX_DEBUG
            printf("Register request\n");
            printf("Service Name: %s\n", reg.service_name().c_str());
            printf("Algorithm ID: %d\n", reg.specs().alg_id());
#endif

            ctx->fido_ctx->operation = FEIDO_OP_REGISTER;
            ctx->fido_ctx->algorithm_id = reg.specs().alg_id();

            size_t srv_len = reg.service_name().length();
            ctx->fido_ctx->service_name = (char *)malloc(srv_len+1);
            // TODO: error handling
            if(!ctx->fido_ctx->service_name) { printf("OOM\n"); assert(false); }

            memcpy(ctx->fido_ctx->service_name, reg.service_name().c_str(), srv_len);
            ctx->fido_ctx->service_name[srv_len] = '\0';

            const int HASH_LEN = EVP_MD_size(EVP_sha256());
            if (HASH_LEN < 0 || sizeof(ctx->fido_ctx->cli_data_hash) != HASH_LEN || reg.clidatahash().length() != HASH_LEN) {
                // TODO: error handling
                printf("Invalid client data hash length\n");
                assert(false);
            }
            memcpy(ctx->fido_ctx->cli_data_hash, reg.clidatahash().c_str(), HASH_LEN);

            break;
        }
        case fido_sgx::FidoRequest::RequestCase::kLogin: {
            fido_sgx::FidoLogin log = request.login();
#ifdef FEIDO_CTX_DEBUG
            printf("Login request\n");
            printf("Service Name: %s\n", log.service_name().c_str());
            printf("Algorithm ID: %d\n", log.specs().alg_id());
#endif

            ctx->fido_ctx->operation = FEIDO_OP_LOGIN;
            ctx->fido_ctx->algorithm_id = log.specs().alg_id();

            size_t srv_len = log.service_name().length();

            ctx->fido_ctx->service_name = (char *)malloc(srv_len+1);
            // TODO: error handling
            if(!ctx->fido_ctx->service_name) { printf("OOM\n"); assert(false); }

            memcpy(ctx->fido_ctx->service_name, log.service_name().c_str(), srv_len);
            ctx->fido_ctx->service_name[srv_len] = '\0';

            const int HASH_LEN = EVP_MD_size(EVP_sha256());
            if (HASH_LEN < 0 || sizeof(ctx->fido_ctx->cli_data_hash) != HASH_LEN || log.clidatahash().length() != HASH_LEN) {
                // TODO: error handling
                printf("Invalid client data hash length\n");
                assert(false);
            }
            memcpy(ctx->fido_ctx->cli_data_hash, log.clidatahash().c_str(), HASH_LEN);

            break;
        }
        case fido_sgx::FidoRequest::RequestCase::REQUEST_NOT_SET:
            printf("No request set\n");
            break;
        default:
            printf("Unknown request\n");
            ctx->state = FEIDO_DO_SHUTDOWN;
            return false;
    }

    ctx->state = FEIDO_WAIT_CA_INIT;
    if (!FEIDO_handle_dgs_and_ca_protocol(ctx)) {
        printf("handle_dgs_ca false\n");
        return false;
    }


    /* WARNING:
     *  while we copy information like the service name and the DG data
     *  buffers explicitly into new heap-located buffers, there might still
     *  be some pointers referring to data inside protobuf messages, which will
     *  not exist anymore from here on, bcs. they will be free'd as part of the
     *  protobuf destructors on return of FEIDO_handle_dgs_and_ca_protocol.
     *
     *  Note that we should check the protobuf _release() functions to find out
     *  if we can use them to avoid extra copying. */


    // If enabled, perform eID revocation check against database server
    //      mimicking Interpol's I-Checkit service
    if (feido_revoke_ctx.feido_query_eid_db == 1) {
        ctx->state = FEIDO_REVOCATION_LOOKUP;
        if (!FEIDO_check_eid_revocation_status(ctx)) {
            printf("eID has been revoked or lookup has failed\n");
            return false;
        }
    }

    ctx->state = FEIDO_FIDO_DERIVE_KEYS;
    if (!FEIDO_FIDO_derive_fido_keys(ctx->fido_ctx)) {
        ctx->state = FEIDO_DO_SHUTDOWN;
        printf("derive_fido_keys false\n");
        return false;
    }

    switch(ctx->fido_ctx->operation) {
        case FEIDO_OP_REGISTER:
            ctx->state = FEIDO_FIDO_REGISTER;
#ifdef FEIDO_CTX_DEBUG
            printf("FIDO register request\n");
#endif
            if (!FEIDO_FIDO_register(ctx)) {
                printf("fido register false\n");
                return false;
            }
            break;
        case FEIDO_OP_LOGIN:
#ifdef FEIDO_CTX_DEBUG
            printf("FIDO login request\n");
#endif
            ctx->state = FEIDO_FIDO_LOGIN;
            if (!FEIDO_FIDO_login(ctx)) {
                printf("fido login false\n");
                return false;
            }
            break;
        case FEIDO_OP_UNDEFINED:
            printf("Invalid operation, error!\n");
            ctx->state = FEIDO_DO_SHUTDOWN;
            return false;
    }

    if(ctx->state != FEIDO_DONE) {
        printf("Expected FEIDO_DONE, but not the case\n");
        assert(false);
    }

    printf("Successfully finished handling of Client request\n");
    return true; // ready for another command run
}

int FEIDO_receive_cli_message(FEIDO_CTX *ctx, SSL *ssl_con, void *recv_buf, size_t recv_len) {
    return FEIDO_do_cli_io(ctx, ssl_con, recv_buf, recv_len, FEIDO_READ);
}

int FEIDO_send_cli_message(FEIDO_CTX *ctx, SSL *ssl_con, const void *send_buf, size_t send_len) {
    return FEIDO_do_cli_io(ctx, ssl_con, (void *)send_buf, send_len, FEIDO_WRITE);
}

int FEIDO_do_cli_io(FEIDO_CTX *ctx, SSL *ssl_con, void *buf, size_t blen, FEIDO_IO_OP op) {
    if (!ctx || !buf) {
        ctx->state = FEIDO_ERROR;
        return -1;
    }

    int ndata;
    switch (op) {
        case FEIDO_READ:
            ndata = SSL_read(ssl_con, buf, blen);
            break;
        case FEIDO_WRITE:
            ndata = SSL_write(ssl_con, buf, blen);
            break;
    }

    if (ndata <= 0) {
#ifdef FEIDO_CTX_DEBUG
        printf("ndata <= 0\n");
#endif
        int ssl_err = SSL_get_error(ssl_con, ndata);
        switch (ssl_err) {
            // syscall/ssl: fatal, don't call shutdown
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                ctx->state = FEIDO_ERROR;
                return false;
            
            default:
                ctx->state = FEIDO_DO_SHUTDOWN;
                return false;
        }
    }
    return ndata;    
}