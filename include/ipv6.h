#ifndef IPV6_H
#define IPV6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IPV6_ADDR_LEN 16

typedef struct {
    uint8_t version;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];
} IPv6Info;

bool decode_ipv6(
    const uint8_t *data,
    size_t length,
    IPv6Info *out
);

const char *ipv6_next_header_name(uint8_t next_header);

void format_ipv6_address(
    const uint8_t address[IPV6_ADDR_LEN],
    char out[40]
);

#endif
