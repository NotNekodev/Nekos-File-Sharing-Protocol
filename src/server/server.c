#include "server.h"

#include <logging.h>
#include <protocol.h>

int port            = NFSP_DEFAULT_PORT;
char cert_path[256] = "/etc/nfsp/certs/client_cert.pem";
char key_path[256]  = "/etc/nfsp/certs/client_key.pem";

void send_chunk(SSL *ssl, FILE *fp, uint32_t seq) {
    uint8_t buffer[NFSP_CHUNK_SIZE];
    size_t bytes = fread(buffer, 1, NFSP_CHUNK_SIZE, fp);
    if (bytes == 0)
        return;

    nfsp_file_data_t *chunk = malloc(sizeof(nfsp_file_data_t) + bytes);
    memcpy(chunk->header.signature, "NFSP", 4);
    chunk->header.version = NFSP_VERSION;
    chunk->header.type    = NFSP_MSG_FILE_DATA;
    chunk->header.length  = sizeof(nfsp_file_data_t) + bytes;
    chunk->seq            = seq;
    chunk->chunk_len      = bytes;
    memcpy(chunk->data, buffer, bytes);
    SHA256(buffer, bytes, chunk->chunk_hash);

    SSL_write(ssl, chunk, sizeof(nfsp_file_data_t) + bytes);
    free(chunk);
}

void handle_server_port_arg(char *value) {
    int port_a = atoi(value);
    if (port_a <= 0 || port_a > 65535) {
        NFSP_ERROR("Invalid port number: %s", value);
        exit(EXIT_FAILURE);
    }
    port = port_a;
}

void handle_server_cert_arg(char *value) {
    if (strlen(value) >= 256) {
        NFSP_ERROR("Certificate filename can't be longer than 255 characters");
        exit(EXIT_FAILURE);
    }

    strncpy(cert_path, value, sizeof(cert_path) - 1);
    cert_path[sizeof(cert_path) - 1] = '\0';
}

void handle_server_key_arg(char *value) {
    if (strlen(value) >= 256) {
        NFSP_ERROR("Key filename can't be longer than 255 characters");
        exit(EXIT_FAILURE);
    }

    strncpy(key_path, value, sizeof(key_path) - 1);
    key_path[sizeof(key_path) - 1] = '\0';
}