#ifndef NFSP_PROTOCOL_H
#define NFSP_PROTOCOL_H

#include <stdint.h>

#define NFSP_MAGIC         0x4E465350
#define NFSP_VERSION       1
#define NFSP_MAX_FILENAME  256
#define NFSP_MAX_ERROR_MSG 256
#define NFSP_MAX_PACKET    4096
#define NFSP_HASH_SIZE     32

typedef enum {
    NFSP_MSG_HELLO = 1,
    NFSP_MSG_FILE_REQUEST,
    NFSP_MSG_FILE_METADATA,
    NFSP_MSG_FILE_DATA,
    NFSP_MSG_FILE_END,
    NFSP_MSG_ERROR,
    NFSP_MSG_CHUNK_ACK
} nfsp_msg_type_t;

typedef enum {
    NFSP_ACK_OK       = 0,
    NFSP_ACK_BAD_HASH = 1
} nfsp_ack_status_t;

typedef struct {
    char signature[4];
    uint16_t version;
    uint16_t type;
    uint32_t length;
} __attribute__((packed)) nfsp_record_header_t;

typedef struct {
    nfsp_record_header_t header;
} __attribute__((packed)) nfsp_hello_t;

typedef struct {
    nfsp_record_header_t header;
    char filename[NFSP_MAX_FILENAME];
} __attribute__((packed)) nfsp_file_request_t;

typedef struct {
    nfsp_record_header_t header;
    uint64_t filesize;
    char filename[NFSP_MAX_FILENAME];
    uint8_t file_hash[NFSP_HASH_SIZE];
} __attribute__((packed)) nfsp_file_metadata_t;

typedef struct {
    nfsp_record_header_t header;
    uint32_t seq;
    uint32_t chunk_len;
    uint8_t chunk_hash[NFSP_HASH_SIZE];
    uint8_t data[];
} __attribute__((packed)) nfsp_file_data_t;

typedef struct {
    nfsp_record_header_t header;
} __attribute__((packed)) nfsp_file_end_t;

typedef struct {
    nfsp_record_header_t header;
    uint32_t code;
    char message[NFSP_MAX_ERROR_MSG];
} __attribute__((packed)) nfsp_error_t;

typedef struct {
    nfsp_record_header_t header;
    uint32_t seq;
    uint8_t status;
} __attribute__((packed)) nfsp_chunk_ack_t;

#endif
