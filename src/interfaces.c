#include <pcap/pcap.h>
#include <stdio.h>

int main(void)
{
    pcap_if_t *devices = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "Could not list interfaces: %s\n", errbuf);
        return 1;
    }

    printf("Network Interfaces\n");
    printf("================================\n");

    if (devices == NULL) {
        printf("No network interfaces found.\n");
        return 0;
    }

    for (pcap_if_t *dev = devices; dev != NULL; dev = dev->next) {
        printf("Name        : %s\n", dev->name);
        printf("Description : %s\n",
               dev->description ? dev->description : "Not available");
        printf("Loopback    : %s\n",
               (dev->flags & PCAP_IF_LOOPBACK) ? "Yes" : "No");
        printf("--------------------------------\n");
    }

    pcap_freealldevs(devices);
    return 0;
}