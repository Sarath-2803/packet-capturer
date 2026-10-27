
#include "ipv6.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_valid_ipv6(void)
{
    const uint8_t packet[40] = {
        0x60, 0x00, 0x00, 0x00, /* Version and traffic fields */
        0x00, 0x00,             /* Payload length */
        0x3A, 0x40,             /* ICMPv6, hop limit 64 */

        /* Source: 2001:db8::1 */
        0x20, 0x01, 0x0D, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1,

        /* Destination: 2001:db8::2 */
        0x20, 0x01, 0x0D, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 2
    };

    IPv6Info info;
    assert(decode_ipv6(packet, sizeof(packet), &info));

    assert(info.version == 6);
    assert(info.payload_length == 0);
    assert(info.next_header == 58);
    assert(info.hop_limit == 64);

    assert(info.src_addr[0] == 0x20);
    assert(info.src_addr[1] == 0x01);
    assert(info.src_addr[15] == 0x01);

    assert(info.dst_addr[0] == 0x20);
    assert(info.dst_addr[15] == 0x02);

    assert(strcmp(ipv6_next_header_name(info.next_header),
                  "ICMPv6") == 0);
}

static void test_truncated_header(void)
{
    const uint8_t packet[39] = {0x60};
    IPv6Info info;

    assert(!decode_ipv6(packet, sizeof(packet), &info));
}

static void test_invalid_version(void)
{
    uint8_t packet[40] = {0};
    IPv6Info info;

    packet[0] = 0x40; /* Version 4, not IPv6 */

    assert(!decode_ipv6(packet, sizeof(packet), &info));
}

static void test_address_formatting(void)
{
    const uint8_t address[16] = {
        0x20, 0x01, 0x0D, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1
    };

    char output[40];
    format_ipv6_address(address, output);

    assert(strcmp(output, "2001:db8:0:0:0:0:0:1") == 0);
}

int main(void)
{
    test_valid_ipv6();
    test_truncated_header();
    test_invalid_version();
    test_address_formatting();

    puts("All IPv6 tests passed.");
    return 0;
}
