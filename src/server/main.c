#include "arg_parser.h"
#include "logging.h"
#include "server.h"

#include <errno.h>
#include <protocol.h>
#include <tls_utils.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {

    init_args(argc, argv);
    add_arg('p', "port", handle_server_port_arg);
    add_arg('c', "cert", handle_server_cert_arg);
    add_arg('k', "key", handle_server_key_arg);
    parse_args();

    SSL_library_init();
    struct ssl_ctx_st *ctx = create_tls_server_context(cert_path, key_path);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        NFSP_ERROR("Socket creation failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = {.sin_family      = AF_INET,
                               .sin_port        = htons(port),
                               .sin_addr.s_addr = INADDR_ANY};

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        NFSP_ERROR("Bind failed: %s", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) != 0) {
        NFSP_ERROR("Listen failed: %s", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    NFSP_INFO("NSFP Server initialized. Listening on port %d", port);
    NFSP_INFO("Using certificate: %s", cert_path);
    NFSP_INFO("Using key: %s", key_path);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    NFSP_INFO("Using %s", SSL_get_version(ssl));
    SSL_shutdown(ssl);
    SSL_free(ssl);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client =
            accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0)
            continue;

        NFSP_INFO("Accepted connection from %s:%d",
                  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // read the request
        nfsp_hello_t hello;
        SSL_read(ssl, &hello, sizeof(hello));
        if (strncmp(hello.header.signature, "NFSP", 4) != 0 ||
            hello.header.version != NFSP_VERSION ||
            hello.header.type != NFSP_MSG_HELLO) {

            nfsp_error_t error;
            memcpy(error.header.signature, "NFSP", 4);
            error.header.version = NFSP_VERSION;
            error.header.type    = NFSP_MSG_ERROR;
            error.header.length  = sizeof(error);
            error.code           = NFSP_MALFORMED_REQUEST;
            strncpy(error.message, "Malformed hello request",
                    NFSP_MAX_ERROR_MSG);
            NFSP_WARNING("Client %s:%d sent malformed hello request",
                         inet_ntoa(client_addr.sin_addr),
                         ntohs(client_addr.sin_port));

            SSL_write(ssl, &error, sizeof(error));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }

        nfsp_file_request_t request;
        SSL_read(ssl, &request, sizeof(request));
        if (strncmp(request.header.signature, "NFSP", 4) != 0 ||
            request.header.version != NFSP_VERSION ||
            request.header.type != NFSP_MSG_FILE_REQUEST) {

            nfsp_error_t error;
            memcpy(error.header.signature, "NFSP", 4);
            error.header.version = NFSP_VERSION;
            error.header.type    = NFSP_MSG_ERROR;
            error.header.length  = sizeof(error);
            error.code           = NFSP_MALFORMED_REQUEST;
            strncpy(error.message, "Malformed file request",
                    NFSP_MAX_ERROR_MSG);

            NFSP_WARNING("Client %s:%d sent malformed request",
                         inet_ntoa(client_addr.sin_addr),
                         ntohs(client_addr.sin_port));

            SSL_write(ssl, &error, sizeof(error));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }

        char filename[NFSP_MAX_FILENAME + 1];
        strncpy(filename, request.filename, NFSP_MAX_FILENAME);

        FILE *fp = fopen(filename, "rb");

        if (fp == NULL) {
            nfsp_error_t error;
            memcpy(error.header.signature, "NFSP", 4);
            error.header.version = NFSP_VERSION;
            error.header.type    = NFSP_MSG_ERROR;
            error.header.length  = sizeof(error);
            error.code           = NFSP_ERROR_FILE;
            strncpy(error.message, strerror(errno), NFSP_MAX_ERROR_MSG);

            NFSP_WARNING("Client %s:%d failed to open file '%s': %s",
                         inet_ntoa(client_addr.sin_addr),
                         ntohs(client_addr.sin_port), filename,
                         strerror(errno));

            SSL_write(ssl, &error, sizeof(error));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);

            continue;
        }

        for (uint32_t seq = 0; !feof(fp); seq++) {
            send_chunk(ssl, fp, seq);
            nfsp_chunk_ack_t ack;

            if (SSL_read(ssl, &ack, sizeof(ack)) <= 0) {
                NFSP_ERROR("Failed to read ACK from client: %s",
                           strerror(errno));
                break;
            }

            if (strncmp(ack.header.signature, "NFSP", 4) != 0 ||
                ack.header.version != NFSP_VERSION ||
                ack.header.type != NFSP_MSG_CHUNK_ACK) {

                nfsp_error_t error;
                memcpy(error.header.signature, "NFSP", 4);
                error.header.version = NFSP_VERSION;
                error.header.type    = NFSP_MSG_ERROR;
                error.header.length  = sizeof(error);
                error.code           = NFSP_MALFORMED_REQUEST;
                strncpy(error.message, "Malformed ACK", NFSP_MAX_ERROR_MSG);

                SSL_write(ssl, &error, sizeof(error));
                break;
            }

            if (ack.status != NFSP_ACK_OK) {
                fseek(fp, -NFSP_CHUNK_SIZE, SEEK_CUR);
                seq--;
            }

            NFSP_DEBUG("Client %s:%d ACKed chunk %u",
                       inet_ntoa(client_addr.sin_addr),
                       ntohs(client_addr.sin_port), seq);
        }

        NFSP_INFO("Client %s:%d finished receiving file '%s'",
                  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
                  filename);

        fclose(fp);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }
    close(sockfd);
    SSL_CTX_free(ctx);
}
