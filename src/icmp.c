
#include "icmp.h"

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

bool decode_icmp(
    const uint8_t *data,
    size_t length,
    ICMPInfo *out)
{
    if (data == NULL || out == NULL || length < 4)
        return false;

    out->type = data[0];
    out->code = data[1];
    out->checksum = read_be16(&data[2]);

    return true;
}

const char *icmp_type_name(uint8_t type, bool is_ipv6)
{
    if (is_ipv6)
    {
        switch (type)
        {
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "Time Exceeded";
        case 4:   return "Parameter Problem";
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        default:  return "Other ICMPv6";
        }
    }

    switch (type)
    {
    case 0:  return "Echo Reply";
    case 3:  return "Destination Unreachable";
    case 5:  return "Redirect";
    case 8:  return "Echo Request";
    case 11: return "Time Exceeded";
    case 12: return "Parameter Problem";
    default: return "Other ICMP";
    }
}
