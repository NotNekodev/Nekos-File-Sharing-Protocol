#ifndef NFSP_SERVER_H
#define NFSP_SERVER_H

#include <openssl/ssl.h>
#include <stdint.h>

void send_chunk(SSL *ssl, FILE *fp, uint32_t seq);

#endif // NFSP_SERVER_H