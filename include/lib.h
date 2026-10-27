#ifndef LIB_H
#define LIB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 6
#define MAX_VLAN_TAGS 4

typedef enum {
    MAC_UNICAST,
    MAC_MULTICAST,
    MAC_BROADCAST
} MacType;

typedef struct {
    uint8_t dst[MAC_LEN];
    uint8_t src[MAC_LEN];

    uint16_t ether_type;
    bool is_8023_length;

    uint16_t vlan_ids[MAX_VLAN_TAGS];
    size_t vlan_count;

    size_t payload_offset;
    size_t captured_length;

    MacType dst_mac_type;
} FrameInfo;

/*
 * Returns true if the frame's Ethernet header is valid enough
 * to decode. Returns false for truncated or malformed headers.
 */
bool decode_ethernet(
    const uint8_t *data,
    size_t length,
    FrameInfo *out
);

MacType classify_mac(const uint8_t mac[MAC_LEN]);

void format_mac(
    const uint8_t mac[MAC_LEN],
    char out[18]
);

const char *mac_type_name(MacType type);

const char *ether_type_name(
    uint16_t ether_type,
    bool is_8023_length
);

#endif