#include "stats.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void stats_init(Stats *stats)
{
    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
}

void stats_record(Stats *stats, const FrameInfo *frame)
{
    if (stats == NULL || frame == NULL)
        return;

    stats->total_frames++;
    stats->total_bytes += frame->captured_length;

    switch (frame->dst_mac_type)
    {
    case MAC_UNICAST:
        stats->unicast_frames++;
        break;
    case MAC_MULTICAST:
        stats->multicast_frames++;
        break;
    case MAC_BROADCAST:
        stats->broadcast_frames++;
        break;
    }

    if (frame->is_8023_length)
    {
        stats->ieee_8023_frames++;
        return;
    }

    stats->ethernet_ii_frames++;

    if (frame->vlan_count > 0)
        stats->vlan_frames++;

    switch (frame->ether_type)
    {
    case 0x0800:
        stats->ipv4_frames++;
        break;
    case 0x86DD:
        stats->ipv6_frames++;
        break;
    case 0x0806:
        stats->arp_frames++;
        break;
    default:
        stats->unknown_frames++;
        break;
    }
}

void stats_record_protocol(
    Stats *stats,
    uint8_t protocol,
    int is_ipv6)
{
    if (stats == NULL)
        return;

    if (is_ipv6)
    {
        switch (protocol)
        {
        case 6:
            stats->tcp_frames++;
            break;
        case 17:
            stats->udp_frames++;
            break;
        case 58:
            stats->icmpv6_frames++;
            break;
        default:
            break;
        }
    }
    else
    {
        switch (protocol)
        {
        case 6:
            stats->tcp_frames++;
            break;
        case 17:
            stats->udp_frames++;
            break;
        case 1:
            stats->icmp_frames++;
            break;
        default:
            break;
        }
    }
}

void stats_print(const Stats *stats)
{
    if (stats == NULL)
        return;

    printf("\nFrame Statistics\n");
    printf("---------------------\n");
    printf("Total frames       : %" PRIu64 "\n", stats->total_frames);
    printf("Total captured bytes: %" PRIu64 "\n", stats->total_bytes);

    printf("Unicast frames     : %" PRIu64 "\n", stats->unicast_frames);
    printf("Multicast frames   : %" PRIu64 "\n", stats->multicast_frames);
    printf("Broadcast frames   : %" PRIu64 "\n", stats->broadcast_frames);

    printf("Ethernet II frames : %" PRIu64 "\n", stats->ethernet_ii_frames);
    printf("IEEE 802.3 frames  : %" PRIu64 "\n", stats->ieee_8023_frames);

    printf("IPv4 frames        : %" PRIu64 "\n", stats->ipv4_frames);
    printf("IPv6 frames        : %" PRIu64 "\n", stats->ipv6_frames);
    printf("ARP frames         : %" PRIu64 "\n", stats->arp_frames);
    printf("VLAN frames        : %" PRIu64 "\n", stats->vlan_frames);
    printf("Unknown protocols  : %" PRIu64 "\n", stats->unknown_frames);

    printf("TCP packets         : %" PRIu64 "\n", stats->tcp_frames);
    printf("UDP packets         : %" PRIu64 "\n", stats->udp_frames);
    printf("ICMP packets        : %" PRIu64 "\n", stats->icmp_frames);
    printf("ICMPv6 packets      : %" PRIu64 "\n", stats->icmpv6_frames);
}