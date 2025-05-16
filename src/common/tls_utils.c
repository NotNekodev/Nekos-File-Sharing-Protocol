#include "tls_utils.h"
#include "logging.h"
#include <openssl/err.h>
#include <openssl/prov_ssl.h>
#include <stdlib.h>

int configure_tls_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    // set the minimum TLS version to 1.3
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        NFSP_ERROR("Failed to set minimum TLS version to TLSv1.3: %s",
                   ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
    return 1;
}

SSL_CTX *create_tls_server_context(const char *cert_file,
                                   const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        return NULL;

    configure_tls_context(ctx);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);

        NFSP_ERROR("Failed to load certificate or key file: %s",
                   ERR_error_string(ERR_get_error(), NULL));

        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL_CTX *create_tls_client_context(const char *cert_file,
                                   const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NULL;

    configure_tls_context(ctx);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        NFSP_ERROR("Failed to load certificate or key file: %s",
                   ERR_error_string(ERR_get_error(), NULL));

        exit(EXIT_FAILURE);
    }
    return ctx;
}
