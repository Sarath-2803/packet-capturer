
#include "transport.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_tcp(void)
{
    const uint8_t packet[20] = {
        0xC3, 0x50, 0x01, 0xBB, /* Ports: 50000 -> 443 */
        0x00, 0x00, 0x00, 0x01, /* Sequence */
        0x00, 0x00, 0x00, 0x02, /* Acknowledgment */
        0x50, 0x12,             /* Header length, SYN + ACK */
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    TransportInfo info;
    assert(decode_tcp(packet, sizeof(packet), &info));

    assert(info.src_port == 50000);
    assert(info.dst_port == 443);
    assert(info.tcp_header_length == 20);
    assert(info.tcp_sequence == 1);
    assert(info.tcp_acknowledgment == 2);
    assert(info.tcp_flags == 0x12);

    char flags[64];
    assert(strcmp(tcp_flags_string(info.tcp_flags, flags, sizeof(flags)),
                  "SYN|ACK") == 0);
}

static void test_tcp_truncated(void)
{
    const uint8_t packet[19] = {0};
    TransportInfo info;

    assert(!decode_tcp(packet, sizeof(packet), &info));
}

static void test_tcp_invalid_header_length(void)
{
    uint8_t packet[20] = {0};
    TransportInfo info;

    packet[12] = 0x40; /* Header length of 16 bytes */

    assert(!decode_tcp(packet, sizeof(packet), &info));
}

static void test_udp(void)
{
    const uint8_t packet[8] = {
        0xC3, 0x50, 0x00, 0x35, /* Ports: 50000 -> 53 */
        0x00, 0x08,             /* UDP length */
        0x00, 0x00              /* Checksum */
    };

    TransportInfo info;
    assert(decode_udp(packet, sizeof(packet), &info));

    assert(info.src_port == 50000);
    assert(info.dst_port == 53);
}

static void test_udp_invalid_length(void)
{
    uint8_t packet[8] = {
        0, 1, 0, 2, 0, 7, 0, 0
    };
    TransportInfo info;

    assert(!decode_udp(packet, sizeof(packet), &info));
}

static void test_empty_tcp_flags(void)
{
    char flags[32];

    assert(strcmp(tcp_flags_string(0, flags, sizeof(flags)), "none") == 0);
}

int main(void)
{
    test_tcp();
    test_tcp_truncated();
    test_tcp_invalid_header_length();
    test_udp();
    test_udp_invalid_length();
    test_empty_tcp_flags();

    puts("All transport tests passed.");
    return 0;
}
