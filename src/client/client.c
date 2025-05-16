#include "client.h"

#include <logging.h>
#include <openssl/sha.h>
#include <protocol.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

char output[256]    = "recv.txt";
int port            = NFSP_DEFAULT_PORT;
char cert_path[256] = "/etc/nfsp/certs/client_cert.pem";
char key_path[256]  = "/etc/nfsp/certs/client_key.pem";

int verify_sha256(uint8_t *data, size_t len, uint8_t *expected) {
    uint8_t hash[32];
    SHA256(data, len, hash);
    return memcmp(hash, expected, 32) == 0;
}

void handle_client_output_arg(char *value) {
    if (strlen(value) >= 256) {
        NFSP_ERROR("Output filename can't be longer than 255 characters");
        exit(EXIT_FAILURE);
    }
    strncpy(output, value, sizeof(output) - 2);
    output[sizeof(output) - 1] = '\0';
}

void handle_client_port_arg(char *value) {
    int port_a = atoi(value);
    if (port_a <= 0 || port_a > 65535) {
        NFSP_ERROR("Invalid port number: %s", value);
        exit(EXIT_FAILURE);
    }
    port = port_a;
}

void handle_client_cert_arg(char *value) {
    if (strlen(value) >= 256) {
        NFSP_ERROR("Certificate filename can't be longer than 255 characters");
        exit(EXIT_FAILURE);
    }

    strncpy(cert_path, value, sizeof(cert_path) - 1);
    cert_path[sizeof(cert_path) - 1] = '\0';
}

void handle_client_key_arg(char *value) {
    if (strlen(value) >= 256) {
        NFSP_ERROR("Key filename can't be longer than 255 characters");
        exit(EXIT_FAILURE);
    }

    strncpy(key_path, value, sizeof(key_path) - 1);
    key_path[sizeof(key_path) - 1] = '\0';
}
