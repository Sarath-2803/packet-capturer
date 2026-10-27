
#include "ipv4.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_valid_ipv4(void)
{
    const uint8_t packet[] = {
        0x45, 0x00, 0x00, 0x28, /* Version, IHL, length */
        0x12, 0x34, 0x40, 0x00, /* ID, flags/fragment */
        0x40, 0x06, 0x00, 0x00, /* TTL, TCP, checksum */
        192, 168, 1, 10,         /* Source IP */
        142, 250, 72, 14         /* Destination IP */
    };

    IPv4Info info;
    assert(decode_ipv4(packet, sizeof(packet), &info));

    assert(info.version == 4);
    assert(info.header_length == 20);
    assert(info.total_length == 40);
    assert(info.identification == 0x1234);
    assert(info.ttl == 64);
    assert(info.protocol == 6);
    assert(info.src_addr == 0xC0A8010A);
    assert(info.dst_addr == 0x8EFA480E);

    assert(strcmp(ipv4_protocol_name(info.protocol), "TCP") == 0);
}

static void test_truncated_header(void)
{
    const uint8_t packet[19] = {0x45};
    IPv4Info info;

    assert(!decode_ipv4(packet, sizeof(packet), &info));
}

static void test_invalid_version(void)
{
    uint8_t packet[20] = {0};
    IPv4Info info;

    packet[0] = 0x65; /* Version 6, with IHL 5 */
    packet[2] = 0;
    packet[3] = 20;

    assert(!decode_ipv4(packet, sizeof(packet), &info));
}

static void test_invalid_header_length(void)
{
    uint8_t packet[20] = {0};
    IPv4Info info;

    packet[0] = 0x44; /* IPv4, but header length is 16 bytes */
    packet[2] = 0;
    packet[3] = 20;

    assert(!decode_ipv4(packet, sizeof(packet), &info));
}

static void test_total_length_smaller_than_header(void)
{
    uint8_t packet[20] = {0};
    IPv4Info info;

    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 19;

    assert(!decode_ipv4(packet, sizeof(packet), &info));
}

static void test_ipv4_options(void)
{
    uint8_t packet[24] = {0};
    IPv4Info info;

    packet[0] = 0x46; /* IPv4 header is 24 bytes */
    packet[2] = 0;
    packet[3] = 24;
    packet[8] = 32;
    packet[9] = 17;

    assert(decode_ipv4(packet, sizeof(packet), &info));
    assert(info.header_length == 24);
    assert(info.total_length == 24);
    assert(info.ttl == 32);
    assert(strcmp(ipv4_protocol_name(info.protocol), "UDP") == 0);
}

int main(void)
{
    test_valid_ipv4();
    test_truncated_header();
    test_invalid_version();
    test_invalid_header_length();
    test_total_length_smaller_than_header();
    test_ipv4_options();

    puts("All IPv4 tests passed.");
    return 0;
}
