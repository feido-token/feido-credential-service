#include "Enclave.h"

extern "C" {
    #include "Enclave_t.h" /* print_string */
}

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <openssl/ssl.h>

extern "C" {
#include "ra-tls/ra-attester.h"
}

#include <eac/eac.h>

#include "fido_sgx.pb.h"

#include "feido_ctx.h"

#include "Enclave_debug.h"

#ifdef FEIDO_GLOBAL_DEBUG
#define FEIDO_ENCLAVE_DEBUG
#endif

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


SSL_CTX *ssl_srv_ctx = NULL;

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    return ctx;
}

int configure_context(SSL_CTX *ctx) {
    uint8_t der_key[4096], der_cert[8192];
    int der_key_len {sizeof(der_key)}, der_cert_len {sizeof(der_cert)};
    create_key_and_x509(der_key, &der_key_len, der_cert, &der_cert_len, &my_ra_tls_options);

    /* Set the key and cert */
/*
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
        return -1;
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 )
        return -1;
*/

    int ret;

    ret = SSL_CTX_use_certificate_ASN1(ctx, der_cert_len, der_cert);
    if (ret != 1) {
        printf("use_certificate_ASN1 failed\n");
        //TODO: cleanup?!
        return -1;
    }

    ret = SSL_CTX_use_RSAPrivateKey_ASN1(ctx, der_key, der_key_len);
    if (ret != 1) {
        printf("use_RSAPrivateKey_ASN1 failed\n");
        //TODO: cleanup?!
        return -1;
    }

    ret = SSL_CTX_check_private_key(ctx); // check that cert and RSA priv. key are consistent!
    if (ret != 1) {
        printf("check_private_key failed\n");
        //TODO: cleanup?!
        return -1;
    }

    // note: anyway default since version 1.1.1
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    return 0;
}

int ecall_init_server_context() {
    printf("Initializing SSL Server context\n");

    /* Init EAC definitions + SSL algorithms! */
    EAC_init();

    /* Load CSCA singleton[?] (BSI root certificates) */
    X509_lookup_csca_cert csca_load = EAC_get_default_csca_lookup();
    if (!csca_load) {
        printf("Failed getting CSCA loader function\n");
        return -1;
    }
    // issuer name hash unused atm (TODO: mark as unused)
    X509_STORE *store = csca_load(0);
    if (!store) {
        printf("Failed loading the CSCA trust store\n");
        return -1;
    }

    if (ssl_srv_ctx) {
        printf("Server SSL Context already initialised\n");
        return -1;
    }

    ssl_srv_ctx = create_context();
    if (!ssl_srv_ctx) {
        printf("Unable to create SSL context\n");
        return -1;
    }

    if (configure_context(ssl_srv_ctx) < 0) {
        printf("Failed setting key and cert\n");
        SSL_CTX_free(ssl_srv_ctx);
        ssl_srv_ctx = NULL;
        return -1;
    }

    printf("Secure SSL Server context is ready\n");
    return 0;
}

void ecall_new_tcp_client(int cli_sock) {
    printf("New client connection (fd: %d)\n", cli_sock);

    FEIDO_CTX *feido_ctx = FEIDO_create_context();
    if (!feido_ctx) {
        printf("Failed context allocation\n");
        return;
    }

    if (!FEIDO_setup_cli_con(feido_ctx, ssl_srv_ctx, cli_sock)) {
        printf("Failed client channel setup\n");
        FEIDO_free_context(feido_ctx);
        return;
    }

    while (FEIDO_handle_cli_cmd(feido_ctx)) feido_ctx->state = FEIDO_WAIT_CMD;

    /* TODO: "must not be called if a previous fatal error has occurred on a
     * connection i.e. if SSL_get_error() has returned SSL_ERROR_SYSCALL or
     * SSL_ERROR_SSL" */
    if (feido_ctx->state == FEIDO_DO_SHUTDOWN) {
        SSL_shutdown(feido_ctx->cli_con.cli_ssl);
    }

    FEIDO_free_context(feido_ctx);

#ifdef FEIDO_ENCLAVE_DEBUG
    printf("Finished\n");
#endif
}