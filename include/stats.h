
#ifndef STATS_H
#define STATS_H

#include "lib.h"

#include <stdint.h>

#ifndef UINT64_MAX
typedef unsigned long long uint64_t;
#endif

typedef struct {
    uint64_t total_frames;
    uint64_t total_bytes;

    uint64_t unicast_frames;
    uint64_t multicast_frames;
    uint64_t broadcast_frames;

    uint64_t ethernet_ii_frames;
    uint64_t ieee_8023_frames;

    uint64_t ipv4_frames;
    uint64_t ipv6_frames;
    uint64_t arp_frames;
    uint64_t vlan_frames;
    uint64_t unknown_frames;

    uint64_t tcp_frames;
    uint64_t udp_frames;
    uint64_t icmp_frames;
    uint64_t icmpv6_frames;
} Stats;

void stats_init(Stats *stats);

void stats_record(
    Stats *stats,
    const FrameInfo *frame
);

void stats_record_protocol(
    Stats *stats,
    uint8_t protocol,
    int is_ipv6
);

void stats_print(const Stats *stats);

#endif
