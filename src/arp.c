#include "ft_malcolm.h"
#include <netinet/if_ether.h>

void display_arp_packet(const unsigned char *packet, size_t length)
{
    struct ether_arp arp;

    if (!packet || length < sizeof(struct ether_arp))
    {
        printf("ft_malcolm: invalid ARP packet\n");
        return;
    }

    memcpy(&arp, packet, sizeof(struct ether_arp));

    if (ntohs(arp.ea_hdr.ar_op) != ARPOP_REQUEST)
        return;

    printf("ARP request detected\n");

    printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp.arp_sha[0], arp.arp_sha[1],
        arp.arp_sha[2], arp.arp_sha[3],
        arp.arp_sha[4], arp.arp_sha[5]);

    printf("Sender IP: %u.%u.%u.%u\n",
        arp.arp_spa[0], arp.arp_spa[1],
        arp.arp_spa[2], arp.arp_spa[3]);

    printf("Target IP: %u.%u.%u.%u\n",
        arp.arp_tpa[0], arp.arp_tpa[1],
        arp.arp_tpa[2], arp.arp_tpa[3]);
}

