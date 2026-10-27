
#include "transport.h"

#include <stdio.h>

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

bool decode_tcp(
    const uint8_t *data,
    size_t length,
    TransportInfo *out)
{
    if (data == NULL || out == NULL || length < 20)
        return false;

    uint8_t header_length = (uint8_t)((data[12] >> 4) * 4);

    if (header_length < 20 || header_length > length)
        return false;

    out->src_port = read_be16(&data[0]);
    out->dst_port = read_be16(&data[2]);
    out->tcp_sequence = read_be32(&data[4]);
    out->tcp_acknowledgment = read_be32(&data[8]);
    out->tcp_header_length = header_length;
    out->tcp_flags = data[13];

    return true;
}

bool decode_udp(
    const uint8_t *data,
    size_t length,
    TransportInfo *out)
{
    if (data == NULL || out == NULL || length < 8)
        return false;

    uint16_t udp_length = read_be16(&data[4]);

    if (udp_length < 8)
        return false;

    out->src_port = read_be16(&data[0]);
    out->dst_port = read_be16(&data[2]);
    out->tcp_header_length = 0;
    out->tcp_flags = 0;
    out->tcp_sequence = 0;
    out->tcp_acknowledgment = 0;

    return true;
}

const char *tcp_flags_string(uint8_t flags, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0)
        return "";

    out[0] = '\0';

    const struct {
        uint8_t mask;
        const char *name;
    } flag_names[] = {
        {0x02, "SYN"},
        {0x10, "ACK"},
        {0x01, "FIN"},
        {0x04, "RST"},
        {0x08, "PSH"},
        {0x20, "URG"},
        {0x40, "ECE"},
        {0x80, "CWR"}
    };

    size_t used = 0;

    for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
        if ((flags & flag_names[i].mask) == 0)
            continue;

        int written = snprintf(out + used, out_size - used,
                               "%s%s",
                               used == 0 ? "" : "|",
                               flag_names[i].name);

        if (written < 0 || (size_t)written >= out_size - used) {
            out[out_size - 1] = '\0';
            break;
        }

        used += (size_t)written;
    }

    if (used == 0)
        snprintf(out, out_size, "none");

    return out;
}
