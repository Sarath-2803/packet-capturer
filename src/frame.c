#include "lib.h"

#include <stdio.h>
#include <string.h>

#define ETH_HEADER_LEN 14
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8
#define ETHERTYPE_VLAN_9100 0x9100

static bool is_vlan_type(uint16_t type)
{
    return type == ETHERTYPE_VLAN ||
           type == ETHERTYPE_QINQ ||
           type == ETHERTYPE_VLAN_9100;
}



MacType classify_mac(const uint8_t mac[MAC_LEN])
{
    static const uint8_t broadcast[MAC_LEN] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    if (memcmp(mac, broadcast, MAC_LEN) == 0)
        return MAC_BROADCAST;

    /* The least-significant bit of the first octet indicates
       a group address: multicast or broadcast. */
    if ((mac[0] & 0x01) != 0)
        return MAC_MULTICAST;

    return MAC_UNICAST;
}

void format_mac(const uint8_t mac[MAC_LEN], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

const char *mac_type_name(MacType type)
{
    switch (type) {
    case MAC_UNICAST:
        return "Unicast";
    case MAC_MULTICAST:
        return "Multicast";
    case MAC_BROADCAST:
        return "Broadcast";
    default:
        return "Unknown";
    }
}

const char *ether_type_name(uint16_t type, bool is_8023_length)
{
    if (is_8023_length)
        return "IEEE 802.3 (length field)";

    switch (type) {
    case 0x0800:
        return "IPv4";
    case 0x0806:
        return "ARP";
    case 0x86DD:
        return "IPv6";
    case 0x8847:
        return "MPLS unicast";
    case 0x8848:
        return "MPLS multicast";
    case 0x88CC:
        return "LLDP";
    default:
        return "Unknown EtherType";
    }
}

bool decode_ethernet(
    const uint8_t *data,
    size_t length,
    FrameInfo *out)
{
    if (data == NULL || out == NULL || length < ETH_HEADER_LEN)
        return false;

    memset(out, 0, sizeof(*out));

    memcpy(out->dst, data, MAC_LEN);
    memcpy(out->src, data + MAC_LEN, MAC_LEN);

    out->captured_length = length;
    out->dst_mac_type = classify_mac(out->dst);

    /*
     * Ethernet bytes 12-13 contain a big-endian type/length field.
     */
    uint16_t type = ((uint16_t)data[12] << 8) | data[13];
    size_t offset = ETH_HEADER_LEN;

    /*
     * Values <= 1500 represent an IEEE 802.3 payload length.
     * Values >= 1536 represent EtherType. The gap is reserved.
     */
    if (type <= 1500) {
        out->is_8023_length = true;
        out->ether_type = type;
        out->payload_offset = offset;
        return true;
    }

    if (type < 1536)
        return false;

    while (is_vlan_type(type)) {
        /*
         * Each VLAN tag contains:
         * 2 bytes TCI + 2 bytes inner EtherType.
         */
        if (out->vlan_count >= MAX_VLAN_TAGS)
            return false;

        if (length - offset < 4)
            return false;

        uint16_t tci = ((uint16_t)data[offset] << 8)
                     | data[offset + 1];

        out->vlan_ids[out->vlan_count] = tci & 0x0FFF;
        out->vlan_count++;

        type = ((uint16_t)data[offset + 2] << 8)
             | data[offset + 3];

        offset += 4;

        if (type <= 1500 || (type > 1500 && type < 1536))
            return false;
    }

    out->ether_type = type;
    out->payload_offset = offset;

    return true;
}