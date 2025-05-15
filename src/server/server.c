#include "server.h"

#include <common.h>
#include <protocol.h>

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