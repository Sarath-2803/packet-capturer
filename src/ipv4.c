#include <stdio.h>
#include "ipv4.h"

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8)  |
           (uint32_t)data[3];
}

bool decode_ipv4(
    const uint8_t *data,
    size_t length,
    IPv4Info *out)
{
    if (data == NULL || out == NULL || length < 20)
        return false;

    uint8_t version = data[0] >> 4;
    uint8_t header_length = (data[0] & 0x0F) * 4;

    if (version != 4 || header_length < 20)
        return false;

    if (length < header_length)
        return false;

    uint16_t total_length = read_be16(&data[2]);

    if (total_length < header_length)
        return false;

    out->version = version;
    out->header_length = header_length;
    out->total_length = total_length;
    out->identification = read_be16(&data[4]);
    out->flags_fragment = read_be16(&data[6]);
    out->ttl = data[8];
    out->protocol = data[9];
    out->src_addr = read_be32(&data[12]);
    out->dst_addr = read_be32(&data[16]);

    return true;
}

const char *ipv4_protocol_name(uint8_t protocol)
{
    switch (protocol) {
    case 1:  return "ICMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6";
    case 47: return "GRE";
    case 50: return "ESP";
    case 51: return "AH";
    case 89: return "OSPF";
    case 132: return "SCTP";
    default: return "Other";
    }
}

void format_ipv4_address(uint32_t address, char out[16])
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (unsigned)((address >> 24) & 0xFF),
             (unsigned)((address >> 16) & 0xFF),
             (unsigned)((address >> 8) & 0xFF),
             (unsigned)(address & 0xFF));
}