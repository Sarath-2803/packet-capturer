
#include "icmp.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_valid_icmpv4(void)
{
    const uint8_t packet[] = {
        8, 0,       /* Echo Request, code 0 */
        0x12, 0x34  /* Checksum */
    };

    ICMPInfo info;

    assert(decode_icmp(packet, sizeof(packet), &info));
    assert(info.type == 8);
    assert(info.code == 0);
    assert(info.checksum == 0x1234);

    assert(strcmp(icmp_type_name(info.type, false),
                  "Echo Request") == 0);
}

static void test_valid_icmpv6(void)
{
    const uint8_t packet[] = {
        129, 0,     /* Echo Reply, code 0 */
        0xAB, 0xCD  /* Checksum */
    };

    ICMPInfo info;

    assert(decode_icmp(packet, sizeof(packet), &info));
    assert(info.type == 129);
    assert(info.code == 0);
    assert(info.checksum == 0xABCD);

    assert(strcmp(icmp_type_name(info.type, true),
                  "Echo Reply") == 0);
}

static void test_truncated_packet(void)
{
    const uint8_t packet[] = {8, 0, 0};
    ICMPInfo info;

    assert(!decode_icmp(packet, sizeof(packet), &info));
}

static void test_null_arguments(void)
{
    const uint8_t packet[] = {8, 0, 0, 0};
    ICMPInfo info;

    assert(!decode_icmp(NULL, sizeof(packet), &info));
    assert(!decode_icmp(packet, sizeof(packet), NULL));
}

static void test_type_names(void)
{
    assert(strcmp(icmp_type_name(3, false),
                  "Destination Unreachable") == 0);

    assert(strcmp(icmp_type_name(135, true),
                  "Neighbor Solicitation") == 0);

    assert(strcmp(icmp_type_name(250, false),
                  "Other ICMP") == 0);
}

int main(void)
{
    test_valid_icmpv4();
    test_valid_icmpv6();
    test_truncated_packet();
    test_null_arguments();
    test_type_names();

    puts("All ICMP tests passed.");
    return 0;
}
