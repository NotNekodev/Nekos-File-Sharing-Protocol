#ifndef NFSP_TLS_UTILS_H
#define NFSP_TLS_UTILS_H

#include <openssl/ssl.h>

SSL_CTX *create_tls_server_context(const char *cert_file, const char *key_file);
SSL_CTX *create_tls_client_context(const char *cert_file, const char *key_file);
int configure_tls_context(SSL_CTX *ctx);

#endif
