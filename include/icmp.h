
#ifndef ICMP_H
#define ICMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} ICMPInfo;

bool decode_icmp(
    const uint8_t *data,
    size_t length,
    ICMPInfo *out
);

const char *icmp_type_name(uint8_t type, bool is_ipv6);

#endif
