
#include "ipv6.h"

#include <stdio.h>
#include <string.h>

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

bool decode_ipv6(
    const uint8_t *data,
    size_t length,
    IPv6Info *out)
{
    if (data == NULL || out == NULL || length < 40)
        return false;

    uint8_t version = data[0] >> 4;

    if (version != 6)
        return false;

    out->version = version;
    out->payload_length = read_be16(&data[4]);
    out->next_header = data[6];
    out->hop_limit = data[7];

    memcpy(out->src_addr, &data[8], IPV6_ADDR_LEN);
    memcpy(out->dst_addr, &data[24], IPV6_ADDR_LEN);

    return true;
}

const char *ipv6_next_header_name(uint8_t next_header)
{
    switch (next_header) {
    case 6:  return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6";
    case 43: return "Routing";
    case 44: return "Fragment";
    case 50: return "ESP";
    case 51: return "AH";
    case 58: return "ICMPv6";
    case 59: return "No Next Header";
    case 60: return "Destination Options";
    default: return "Other";
    }
}

void format_ipv6_address(
    const uint8_t address[IPV6_ADDR_LEN],
    char out[40])
{
    if (address == NULL || out == NULL)
        return;

    snprintf(out, 40,
             "%x:%x:%x:%x:%x:%x:%x:%x",
             (unsigned)((address[0] << 8) | address[1]),
             (unsigned)((address[2] << 8) | address[3]),
             (unsigned)((address[4] << 8) | address[5]),
             (unsigned)((address[6] << 8) | address[7]),
             (unsigned)((address[8] << 8) | address[9]),
             (unsigned)((address[10] << 8) | address[11]),
             (unsigned)((address[12] << 8) | address[13]),
             (unsigned)((address[14] << 8) | address[15]));
}
