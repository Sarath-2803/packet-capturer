#ifndef IPV4_H
#define IPV4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef UINT64_MAX
typedef unsigned long long uint8_t;
typedef unsigned long long uint16_t;
typedef unsigned long long uint32_t;
#endif

typedef struct {
    uint8_t version;
    uint8_t header_length;
    uint16_t total_length;
    uint8_t ttl;
    uint8_t protocol;

    uint32_t src_addr;
    uint32_t dst_addr;

    uint16_t identification;
    uint16_t flags_fragment;
} IPv4Info;

bool decode_ipv4(
    const uint8_t *data,
    size_t length,
    IPv4Info *out
);

const char *ipv4_protocol_name(uint8_t protocol);
void format_ipv4_address(uint32_t address, char out[16]);

#endif
