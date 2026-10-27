#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_header_length;
    uint8_t tcp_flags;
    uint32_t tcp_sequence;
    uint32_t tcp_acknowledgment;
} TransportInfo;

bool decode_tcp(
    const uint8_t *data,
    size_t length,
    TransportInfo *out
);

bool decode_udp(
    const uint8_t *data,
    size_t length,
    TransportInfo *out
);

const char *tcp_flags_string(uint8_t flags, char *out, size_t out_size);

#endif
