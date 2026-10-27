#include "lib.h"

#include <stdio.h>

int main(void)
{
    /*
     * Synthetic Ethernet frame:
     * Destination MAC: 01:00:5E:00:00:FB (multicast)
     * Source MAC:      02:11:22:33:44:55 (unicast)
     * VLAN ID:         100
     * Inner EtherType: 0x0800 (IPv4)
     *
     * The remaining bytes are a minimal sample payload.
     * This is test data, not a real captured packet.
     */
    const uint8_t frame[] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB,
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x81, 0x00,
        0x00, 0x64,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,
        0xC0, 0xA8, 0x01, 0x02
    };

    FrameInfo info;

    if (!decode_ethernet(frame, sizeof(frame), &info)) {
        fprintf(stderr, "Error: invalid or truncated Ethernet frame\n");
        return 1;
    }

    char dst_mac[18];
    char src_mac[18];

    format_mac(info.dst, dst_mac);
    format_mac(info.src, src_mac);

    printf("FrameScope - Core Decoder Test\n");
    printf("==============================\n");
    printf("Captured length : %zu bytes\n", info.captured_length);
    printf("Destination MAC : %s\n", dst_mac);
    printf("Source MAC      : %s\n", src_mac);
    printf("Destination type: %s\n",
           mac_type_name(info.dst_mac_type));

    printf("Frame format    : %s\n",
           info.is_8023_length ? "IEEE 802.3" : "Ethernet II");

    printf("VLAN tag count  : %zu\n", info.vlan_count);

    for (size_t i = 0; i < info.vlan_count; i++) {
        printf("VLAN %zu ID       : %u\n",
               i + 1, (unsigned)info.vlan_ids[i]);
    }

    printf("EtherType       : 0x%04X\n", info.ether_type);
    printf("Protocol        : %s\n",
           ether_type_name(info.ether_type,
                              info.is_8023_length));
    printf("Payload offset  : %zu bytes\n", info.payload_offset);

    return 0;
}