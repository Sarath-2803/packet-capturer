
#include "arp.h"

#include <string.h>
#include <stdio.h>

#define ARP_ETHERNET_IPV4_LENGTH 28

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

bool decode_arp(
    const uint8_t *data,
    size_t length,
    ARPInfo *out)
{
    if (data == NULL || out == NULL ||
        length < ARP_ETHERNET_IPV4_LENGTH)
    {
        return false;
    }

    uint16_t hardware_type = read_be16(&data[0]);
    uint16_t protocol_type = read_be16(&data[2]);
    uint8_t hardware_length = data[4];
    uint8_t protocol_length = data[5];

    /* This decoder supports Ethernet carrying IPv4 only. */
    if (hardware_type != 1 ||
        protocol_type != 0x0800 ||
        hardware_length != 6 ||
        protocol_length != 4)
    {
        return false;
    }

    out->hardware_type = hardware_type;
    out->protocol_type = protocol_type;
    out->hardware_length = hardware_length;
    out->protocol_length = protocol_length;
    out->operation = read_be16(&data[6]);

    memcpy(out->sender_mac, &data[8], 6);
    memcpy(out->sender_ip, &data[14], 4);
    memcpy(out->target_mac, &data[18], 6);
    memcpy(out->target_ip, &data[24], 4);

    return true;
}

const char *arp_operation_name(uint16_t operation)
{
    switch (operation)
    {
    case 1:
        return "Request";
    case 2:
        return "Reply";
    default:
        return "Other";
    }
}

void format_arp_ipv4(const uint8_t address[4], char out[16])
{
    if (address == NULL || out == NULL)
        return;

    snprintf(out, 16, "%u.%u.%u.%u",
             (unsigned)address[0],
             (unsigned)address[1],
             (unsigned)address[2],
             (unsigned)address[3]);
}
