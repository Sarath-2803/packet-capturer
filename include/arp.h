
#ifndef ARP_H
#define ARP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;

    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} ARPInfo;

bool decode_arp(
    const uint8_t *data,
    size_t length,
    ARPInfo *out
);

const char *arp_operation_name(uint16_t operation);

void format_arp_ipv4(const uint8_t address[4], char out[16]);

#endif
