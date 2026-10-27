#include "lib.h"

#include <assert.h>
#include <stdio.h>

static void test_unicast_mac(void)
{
    const uint8_t mac[6] = {
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55
    };

    assert(classify_mac(mac) == MAC_UNICAST);
}

static void test_multicast_mac(void)
{
    const uint8_t mac[6] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB
    };

    assert(classify_mac(mac) == MAC_MULTICAST);
}

static void test_broadcast_mac(void)
{
    const uint8_t mac[6] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    assert(classify_mac(mac) == MAC_BROADCAST);
}

static void test_truncated_frame(void)
{
    const uint8_t frame[13] = {0};
    FrameInfo info;

    assert(!decode_ethernet(frame, sizeof(frame), &info));
}

static void test_vlan_frame(void)
{
    const uint8_t frame[] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB,
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x81, 0x00,             /* VLAN EtherType */
        0x00, 0x64,             /* VLAN ID 100 */
        0x08, 0x00,             /* IPv4 EtherType */
        0x45, 0x00
    };

    FrameInfo info;

    assert(decode_ethernet(frame, sizeof(frame), &info));
    assert(info.vlan_count == 1);
    assert(info.vlan_ids[0] == 100);
    assert(info.ether_type == 0x0800);
    assert(info.payload_offset == 18);
}

int main(void)
{
    test_unicast_mac();
    test_multicast_mac();
    test_broadcast_mac();
    test_truncated_frame();
    test_vlan_frame();

    puts("All FrameScope core tests passed.");
    return 0;
}