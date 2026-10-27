#include "lib.h"
#include "stats.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    const uint8_t frame[] = {
        0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB,
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x81, 0x00,
        0x00, 0x64,
        0x08, 0x00,
        0x45, 0x00
    };

    FrameInfo info;
    Stats stats;

    assert(decode_ethernet(frame, sizeof(frame), &info));

    stats_init(&stats);
    stats_record(&stats, &info);

    assert(stats.total_frames == 1);
    assert(stats.total_bytes == sizeof(frame));
    assert(stats.multicast_frames == 1);
    assert(stats.vlan_frames == 1);
    assert(stats.ipv4_frames == 1);
    assert(stats.ethernet_ii_frames == 1);

    stats_print(&stats);

    puts("\nAll FrameScope statistics tests passed.");
    return 0;
}