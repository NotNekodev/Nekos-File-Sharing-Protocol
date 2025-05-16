#ifndef NFSP_CLIENT_H
#define NFSP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

extern char output[256];
extern int port;
extern char cert_path[256];
extern char key_path[256];

int verify_sha256(uint8_t *data, size_t len, uint8_t *expected);

void handle_client_output_arg(char *value);
void handle_client_port_arg(char *value);
void handle_client_cert_arg(char *value);
void handle_client_key_arg(char *value);

#endif // NFSP_CLIENT_H