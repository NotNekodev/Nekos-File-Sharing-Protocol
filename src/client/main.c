#include "client.h"

#include <logging.h>
#include <protocol.h>
#include <tls_utils.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arg_parser.h>

int main(int argc, char *argv[]) {
    char **positional_args = init_args(argc, argv);
    if (positional_args[0] == NULL || positional_args[1] == NULL) {
        NFSP_ERROR("Usage: %s <server_ip> <filename> [options]\n", argv[0]);
        return 1;
    }
    add_arg('o', "output", handle_client_output_arg);
    add_arg('p', "port", handle_client_port_arg);
    add_arg('c', "cert", handle_client_cert_arg);
    add_arg('k', "key", handle_client_key_arg);
    parse_args();

    SSL_library_init();
    SSL_CTX *ctx = create_tls_client_context(cert_path, key_path);

    int sockfd              = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, positional_args[0], &addr.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        NFSP_ERROR("Failed to connect to %s:%d: %s", positional_args[0], port,
                   strerror(errno));
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0)
        return 1;

    nfsp_hello_t hello;
    memcpy(hello.header.signature, "NFSP", 4);
    hello.header.version = NFSP_VERSION;
    hello.header.type    = NFSP_MSG_HELLO;
    hello.header.length  = sizeof(hello);
    SSL_write(ssl, &hello, sizeof(hello));

    nfsp_file_request_t request;
    memcpy(request.header.signature, "NFSP", 4);
    request.header.version = NFSP_VERSION;
    request.header.type    = NFSP_MSG_FILE_REQUEST;
    request.header.length  = sizeof(request);
    strncpy(request.filename, positional_args[1], NFSP_MAX_FILENAME);
    SSL_write(ssl, &request, sizeof(request));

    FILE *out = fopen(output, "wb");
    while (1) {
        nfsp_file_data_t header;
        int read = SSL_read(ssl, &header, sizeof(header));
        if (read <= 0 || header.header.type != NFSP_MSG_FILE_DATA) {
            if (read <= 0) {
                nfsp_error_t *error = (nfsp_error_t *)&header;
                if (error->code == 0) {
                    NFSP_SUCCESS("Received %s:%d/%s -> %s", positional_args[0],
                                 port, positional_args[1], output);
                    break;
                }
                NFSP_ERROR("Failed to read from server (0x%.4lx): %s",
                           error->code, error->message);

                fclose(out);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);
                SSL_CTX_free(ctx);

                exit(EXIT_FAILURE);
            } else {
                // handle error message
                nfsp_error_t *error = (nfsp_error_t *)&header;
                if (strncmp(error->header.signature, "NFSP", 4) != 0 ||
                    error->header.version != NFSP_VERSION ||
                    error->header.type != NFSP_MSG_ERROR) {
                    NFSP_ERROR("Malformed response from the server");

                    fclose(out);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(sockfd);
                    SSL_CTX_free(ctx);

                    exit(EXIT_FAILURE);
                } else {
                    NFSP_ERROR("Error Retrieving file (0x%.4lx): %s",
                               error->code, error->message);

                    fclose(out);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(sockfd);
                    SSL_CTX_free(ctx);

                    exit(EXIT_FAILURE);
                }
            }
        }

        size_t data_len = header.chunk_len;
        uint8_t *data   = malloc(data_len);
        SSL_read(ssl, data, data_len);

        nfsp_chunk_ack_t ack;
        memcpy(ack.header.signature, "NFSP", 4);
        ack.header.version = NFSP_VERSION;
        ack.header.type    = NFSP_MSG_CHUNK_ACK;
        ack.header.length  = sizeof(ack);
        ack.seq            = header.seq;
        ack.status         = verify_sha256(data, data_len, header.chunk_hash)
                                 ? NFSP_ACK_OK
                                 : NFSP_ACK_BAD_HASH;

        if (ack.status == NFSP_ACK_OK)
            fwrite(data, 1, data_len, out);
        SSL_write(ssl, &ack, sizeof(ack));
        free(data);
    }

    fclose(out);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}
