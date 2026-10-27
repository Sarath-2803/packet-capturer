
#include "arp.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_arp_request(void)
{
    const uint8_t packet[28] = {
        0x00, 0x01,             /* Ethernet */
        0x08, 0x00,             /* IPv4 */
        0x06, 0x04,             /* MAC length 6, IPv4 length 4 */
        0x00, 0x01,             /* ARP request */

        /* Sender MAC: 00:11:22:33:44:55 */
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,

        /* Sender IP: 192.168.1.10 */
        192, 168, 1, 10,

        /* Target MAC: unknown */
        0, 0, 0, 0, 0, 0,

        /* Target IP: 192.168.1.1 */
        192, 168, 1, 1
    };

    ARPInfo info;

    assert(decode_arp(packet, sizeof(packet), &info));

    assert(info.hardware_type == 1);
    assert(info.protocol_type == 0x0800);
    assert(info.hardware_length == 6);
    assert(info.protocol_length == 4);
    assert(info.operation == 1);

    assert(info.sender_mac[0] == 0x00);
    assert(info.sender_mac[5] == 0x55);
    assert(info.sender_ip[0] == 192);
    assert(info.sender_ip[3] == 10);
    assert(info.target_ip[0] == 192);
    assert(info.target_ip[3] == 1);

    assert(strcmp(arp_operation_name(info.operation),
                  "Request") == 0);
}

static void test_arp_reply(void)
{
    uint8_t packet[28] = {
        0x00, 0x01,
        0x08, 0x00,
        0x06, 0x04,
        0x00, 0x02
    };

    ARPInfo info;

    assert(decode_arp(packet, sizeof(packet), &info));
    assert(info.operation == 2);

    assert(strcmp(arp_operation_name(info.operation),
                  "Reply") == 0);
}

static void test_truncated_packet(void)
{
    uint8_t packet[27] = {0};
    ARPInfo info;

    assert(!decode_arp(packet, sizeof(packet), &info));
}

static void test_invalid_hardware_type(void)
{
    uint8_t packet[28] = {
        0x00, 0x02, /* Unsupported hardware type */
        0x08, 0x00,
        0x06, 0x04,
        0x00, 0x01
    };

    ARPInfo info;

    assert(!decode_arp(packet, sizeof(packet), &info));
}

static void test_invalid_address_lengths(void)
{
    uint8_t packet[28] = {
        0x00, 0x01,
        0x08, 0x00,
        0x05, 0x04, /* Incorrect MAC length */
        0x00, 0x01
    };

    ARPInfo info;

    assert(!decode_arp(packet, sizeof(packet), &info));

    packet[4] = 6;
    packet[5] = 16; /* Incorrect IPv4 address length */

    assert(!decode_arp(packet, sizeof(packet), &info));
}

static void test_null_arguments(void)
{
    uint8_t packet[28] = {0};
    ARPInfo info;

    assert(!decode_arp(NULL, sizeof(packet), &info));
    assert(!decode_arp(packet, sizeof(packet), NULL));
}

static void test_address_formatting(void)
{
    const uint8_t address[4] = {192, 168, 1, 10};
    char output[16];

    format_arp_ipv4(address, output);

    assert(strcmp(output, "192.168.1.10") == 0);
}

static void test_unknown_operation(void)
{
    assert(strcmp(arp_operation_name(99), "Other") == 0);
}

int main(void)
{
    test_arp_request();
    test_arp_reply();
    test_truncated_packet();
    test_invalid_hardware_type();
    test_invalid_address_lengths();
    test_null_arguments();
    test_address_formatting();
    test_unknown_operation();

    puts("All ARP tests passed.");
    return 0;
}
