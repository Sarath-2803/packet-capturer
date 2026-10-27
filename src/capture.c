#include "lib.h"
#include "stats.h"
#include "ipv4.h"
#include "transport.h"
#include "icmp.h"
#include "ipv6.h"
#include "arp.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define PACKET_LIMIT 20

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 3)
    {
        fprintf(stderr, "Usage: %s <interface> [filter]\n", argv[0]);
        return 1;
    }

    const char *interface = argv[1];
    const char *filter = (argc == 3) ? argv[2] : NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(
        interface,
        65535, /* Snapshot length */
        1,     /* Enable promiscuous mode */
        1000,  /* Read timeout in milliseconds */
        errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Could not open %s: %s\n", interface, errbuf);
        return 1;
    }

    int link_type = pcap_datalink(handle);

    if (link_type != DLT_EN10MB)
    {
        fprintf(stderr,
                "Unsupported link-layer type %d. "
                "This decoder requires Ethernet (DLT_EN10MB).\n",
                link_type);
        pcap_close(handle);
        return 1;
    }

    if (filter != NULL)
    {
        struct bpf_program program;

        if (pcap_compile(handle, &program, filter, 1,
                         PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "Invalid filter: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }

        if (pcap_setfilter(handle, &program) == -1)
        {
            fprintf(stderr, "Could not apply filter: %s\n",
                    pcap_geterr(handle));
            pcap_freecode(&program);
            pcap_close(handle);
            return 1;
        }

        pcap_freecode(&program);
    }

    Stats stats;
    stats_init(&stats);

    printf("FrameScope live capture on %s\n", interface);
    printf("Capturing up to %d packets. Press Ctrl+C to stop early.\n\n",
           PACKET_LIMIT);

    for (int i = 0; i < PACKET_LIMIT;)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 0)
            continue; /* Read timeout; try again. */

        if (result == -2)
            break; /* Capture ended. */

        if (result == -1)
        {
            fprintf(stderr, "Capture error: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }

        FrameInfo info;

        if (!decode_ethernet(packet, header->caplen, &info))
        {
            printf("Skipped malformed or unsupported Ethernet header\n");
            continue;
        }

        stats_record(&stats, &info);

        char src[18];
        char dst[18];

        format_mac(info.src, src);
        format_mac(info.dst, dst);

        printf("%2d. %s -> %s | %-9s | %s | %u bytes\n",
               i + 1,
               src,
               dst,
               mac_type_name(info.dst_mac_type),
               ether_type_name(info.ether_type,
                               info.is_8023_length),
               header->caplen);

        if (!info.is_8023_length && info.ether_type == 0x0800)
        {
            IPv4Info ip_info;

            size_t remaining = header->caplen - info.payload_offset;

            if (decode_ipv4(packet + info.payload_offset,
                            remaining,
                            &ip_info))
            {
                char src_ip[16];
                char dst_ip[16];

                format_ipv4_address(ip_info.src_addr, src_ip);
                format_ipv4_address(ip_info.dst_addr, dst_ip);

                printf("    IPv4: %s -> %s | %-4s | TTL: %u"
                       " | IP length: %u bytes\n",
                       src_ip,
                       dst_ip,
                       ipv4_protocol_name(ip_info.protocol),
                       ip_info.ttl,
                       ip_info.total_length);
                    
                stats_record_protocol(&stats, ip_info.protocol, 0);

                size_t ip_payload_length = ip_info.total_length - ip_info.header_length;
                size_t captured_ip_length = header->caplen - info.payload_offset;

                if (captured_ip_length > ip_info.header_length)
                {
                    captured_ip_length -= ip_info.header_length;
                }
                else
                {
                    captured_ip_length = 0;
                }

                size_t transport_length = ip_payload_length < captured_ip_length
                                              ? ip_payload_length
                                              : captured_ip_length;

                bool is_fragment = (ip_info.flags_fragment & 0x1FFF) != 0;

                if (!is_fragment && transport_length > 0)
                {
                    const uint8_t *transport_data =
                        packet + info.payload_offset + ip_info.header_length;

                    TransportInfo transport;

                    if (ip_info.protocol == 6 &&
                        decode_tcp(transport_data, transport_length, &transport))
                    {
                        char flags[64];

                        printf("    TCP:  %u -> %u | Flags: %s | Header: %u bytes\n",
                               transport.src_port,
                               transport.dst_port,
                               tcp_flags_string(transport.tcp_flags, flags, sizeof(flags)),
                               transport.tcp_header_length);
                    }
                    else if (ip_info.protocol == 17 &&
                             decode_udp(transport_data, transport_length, &transport))
                    {
                        printf("    UDP:  %u -> %u\n",
                               transport.src_port,
                               transport.dst_port);
                    }
                }

                if (ip_info.protocol == 1 && transport_length >= 4)
                {
                    const uint8_t *icmp_data =
                        packet + info.payload_offset + ip_info.header_length;

                    ICMPInfo icmp;

                    if (decode_icmp(icmp_data, transport_length, &icmp))
                    {
                        printf("    ICMP: %s | Type: %u | Code: %u"
                               " | Checksum: 0x%04X\n",
                               icmp_type_name(icmp.type, false),
                               icmp.type,
                               icmp.code,
                               icmp.checksum);
                    }
                }
            }
            else
            {
                printf("    Invalid or truncated IPv4 header\n");
            }
        }

        if (!info.is_8023_length && info.ether_type == 0x86DD)
        {
            IPv6Info ip6;

            size_t remaining = header->caplen - info.payload_offset;

            if (decode_ipv6(packet + info.payload_offset,
                            remaining, &ip6))
            {
                char src_ip[40];
                char dst_ip[40];

                format_ipv6_address(ip6.src_addr, src_ip);
                format_ipv6_address(ip6.dst_addr, dst_ip);

                printf("    IPv6: %s -> %s\n", src_ip, dst_ip);

                printf("    Next header: %-18s | Hop limit: %u"
                       " | Payload: %u bytes\n",
                       ipv6_next_header_name(ip6.next_header),
                       ip6.hop_limit,
                       ip6.payload_length);

                stats_record_protocol(&stats, ip6.next_header, 1);

                if (ip6.next_header == 58 && remaining >= 4)
                {
                    const uint8_t *icmp_data =
                        packet + info.payload_offset + 40;

                    ICMPInfo icmp;

                    if (decode_icmp(icmp_data, remaining, &icmp))
                    {
                        printf("    ICMPv6: %s | Type: %u | Code: %u"
                               " | Checksum: 0x%04X\n",
                               icmp_type_name(icmp.type, true),
                               icmp.type,
                               icmp.code,
                               icmp.checksum);
                    }
                }
            }
            else
            {
                printf("    Invalid or truncated IPv6 header\n");
            }
        }

        if (!info.is_8023_length && info.ether_type == 0x0806)
        {
            ARPInfo arp;

            size_t remaining = (size_t)header->caplen -
                               info.payload_offset;

            if (decode_arp(packet + info.payload_offset,
                           remaining, &arp))
            {
                char sender_ip[16];
                char target_ip[16];
                char sender_mac[18];
                char target_mac[18];

                format_arp_ipv4(arp.sender_ip, sender_ip);
                format_arp_ipv4(arp.target_ip, target_ip);
                format_mac(arp.sender_mac, sender_mac);
                format_mac(arp.target_mac, target_mac);

                printf("    ARP %s\n",
                       arp_operation_name(arp.operation));

                printf("    Sender: %s (%s)\n",
                       sender_ip, sender_mac);

                printf("    Target: %s (%s)\n",
                       target_ip, target_mac);
            }
            else
            {
                printf("    Invalid or unsupported ARP packet\n");
            }
        }

        i++;
    }

    stats_print(&stats);
    pcap_close(handle);

    return 0;
}