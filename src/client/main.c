#include "common.h"
#include "protocol.h"
#include "tls_utils.h"
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int verify_sha256(uint8_t *data, size_t len, uint8_t *expected) {
    uint8_t hash[32];
    SHA256(data, len, hash);
    return memcmp(hash, expected, 32) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <filename> [options]\n",
                argv[0]);
        return 1;
    }

    int NFSP_PORT = NFSP_PORT_DEFAULT;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                int port = atoi(argv[i + 1]);
                if (port > 0 && port <= 65535) {
                    NFSP_PORT = port;
                } else {
                    fprintf(stderr, "Invalid port number: %s\n", argv[i + 1]);
                    exit(EXIT_FAILURE);
                }
            } else {
                fprintf(stderr, "Missing port number after %s\n", argv[i]);
                exit(EXIT_FAILURE);
            }
        }
    }
    SSL_library_init();
    SSL_CTX *ctx = create_tls_client_context("certs/client_cert.pem",
                                             "certs/client_key.pem");

    int sockfd              = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_port   = htons(NFSP_PORT)};
    inet_pton(AF_INET, argv[1], &addr.sin_addr);
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

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
    strncpy(request.filename, argv[2], NFSP_MAX_FILENAME);
    SSL_write(ssl, &request, sizeof(request));

    FILE *out = fopen("recv.txt", "wb");
    while (1) {
        nfsp_file_data_t header;
        int read = SSL_read(ssl, &header, sizeof(header));
        if (read <= 0 || header.header.type != NFSP_MSG_FILE_DATA)
            break;

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
