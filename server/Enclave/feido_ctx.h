#ifndef _FEIDO_CTX_H_
#define _FEIDO_CTX_H_

#include "fido_sgx_sod_dg.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>

#if defined(__cplusplus)
extern "C" {
#endif

enum feido_fido_op { FEIDO_OP_UNDEFINED, FEIDO_OP_REGISTER, FEIDO_OP_LOGIN };

/*
 * operation:       FIDO2 request type
 * service_name:    service/server of FIDO2
 * fido_key:        (attribute-derived) client FIDO2 key pair
 */
typedef struct feido_fido_ctx {
    enum feido_fido_op operation;
    char *service_name;
    int algorithm_id; // TODO: consider as attribute in key derivation?
    EVP_PKEY *fido_key;
    uint8_t cli_data_hash[32]; //sha-256
//    uint8_t *login_challenge; // implicitly in cli_data_hash?
//    size_t chllng_len;
    FORM_DG1 *personal_data;
}FEIDO_FIDO_CTX;

/* cli_ssl: RA-TLS client context */
typedef struct feido_connection_ctx {
    SSL *cli_ssl;
} FEIDO_CONN;

typedef enum feido_state {
    FEIDO_ERROR = -1,

    FEIDO_NO_CLI = 0, // client TLS channel ->
    FEIDO_WAIT_CMD, // <fido_cmd> ->

    FEIDO_WAIT_CA_INIT, // DGs and ePassport public key ->
    FEIDO_SEND_CA_EPHM_PKEY, // <sent> ->
    FEIDO_SEND_CA_TA_INIT_CMD, // <sent> ->
    FEIDO_WAIT_CA_TA_NONCE, // TA nonce/challenge ->
    FEIDO_CA_DONE,

    FEIDO_REVOCATION_LOOKUP, // optional: query eID revocation database service

    FEIDO_FIDO_DERIVE_KEYS,

    FEIDO_FIDO_REGISTER, // <sent public key> ->
    FEIDO_FIDO_LOGIN, // <sent signed challenge> ->

    FEIDO_DONE, // -> back to WAIT_CMD or to DO_SHUTDOWN
    FEIDO_DO_SHUTDOWN,
} FEIDO_STATE;

/* main struct for a client-enclave session
 * 
 * cli_con:     communication channel to client (RA-TLS connection)
 * epass_ctx:   ePassport information (DataGroups, ChipAuthentication)
 * fido_ctx:    information about current FIDO2 client request
 */
typedef struct feido_context {
    FEIDO_STATE state;
    FEIDO_CONN cli_con;
    EPASS_CTX *epass_ctx;
    FEIDO_FIDO_CTX *fido_ctx;
} FEIDO_CTX;

FEIDO_CTX *FEIDO_create_context(void);
void FEIDO_free_context(FEIDO_CTX *ctx);

/* I/O Utils */
int FEIDO_receive_cli_message(FEIDO_CTX *ctx, SSL *ssl_con, void *recv_buf, size_t recv_len);
int FEIDO_send_cli_message(FEIDO_CTX *ctx, SSL *ssl_con, const void *send_buf, size_t send_len);

/* FEIDO_NO_CLI -> FEIDO_WAIT_CMD */
bool FEIDO_setup_cli_con(FEIDO_CTX *ctx, SSL_CTX *srv_ctx, int sock_fd);

/* FEIDO_WAIT_CMD -> FEIDO_DONE/ERROR */
bool FEIDO_handle_cli_cmd(FEIDO_CTX *ctx);

extern SSL_CTX *ssl_srv_ctx;

#if defined(__cplusplus)
}
#endif

#endif /* !_FEIDO_CTX_H_ */