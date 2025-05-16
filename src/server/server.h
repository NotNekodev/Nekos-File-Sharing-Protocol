#ifndef NFSP_SERVER_H
#define NFSP_SERVER_H

#include <openssl/ssl.h>
#include <stdint.h>

extern int port;
extern char cert_path[256];
extern char key_path[256];

void send_chunk(SSL *ssl, FILE *fp, uint32_t seq);

void handle_server_port_arg(char *value);
void handle_server_cert_arg(char *value);
void handle_server_key_arg(char *value);

#endif // NFSP_SERVER_H