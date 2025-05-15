#include "server.h"

#include <common.h>
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

    int NFSP_PORT = NFSP_PORT_DEFAULT;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s\n", argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "--version") == 0 ||
                   strcmp(argv[i], "-v") == 0) {
            printf("Version: %s\n", "go fuck yourself");
            exit(0);
        } else if (strcmp(argv[i], "--port") == 0 ||
                   strcmp(argv[i], "-p") == 0) {
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
    SSL_CTX *ctx = create_tls_server_context("certs/server_cert.pem",
                                             "certs/server_key.pem");

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = {.sin_family      = AF_INET,
                               .sin_port        = htons(NFSP_PORT),
                               .sin_addr.s_addr = INADDR_ANY};

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) != 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int client = accept(sockfd, NULL, NULL);
        SSL *ssl   = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0)
            continue;

        // read the request
        nfsp_hello_t hello;
        SSL_read(ssl, &hello, sizeof(hello));
        if (strncmp(hello.header.signature, "NFSP", 4) != 0 ||
            hello.header.version != NFSP_VERSION ||
            hello.header.type != NFSP_MSG_HELLO) {
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
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }

        char filename[NFSP_MAX_FILENAME + 1];
        strncpy(filename, request.filename, NFSP_MAX_FILENAME);

        FILE *fp = fopen(filename, "rb");
        for (uint32_t seq = 0; !feof(fp); seq++) {
            send_chunk(ssl, fp, seq);
            nfsp_chunk_ack_t ack;
            SSL_read(ssl, &ack, sizeof(ack));
            if (ack.status != NFSP_ACK_OK) {
                fseek(fp, -NFSP_CHUNK_SIZE, SEEK_CUR);
                seq--;
            }
        }
        fclose(fp);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }
    close(sockfd);
    SSL_CTX_free(ctx);
}
