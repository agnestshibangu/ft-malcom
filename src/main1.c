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
     * Open a passive ARP socket.
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
     * Receive packets until Ctrl+C.
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
         * Only display ARP requests.
         */
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST)
            continue;

        /*
         * Only requests concerning our configured source IP.
         */
        if (memcmp(arp->arp_tpa, &data.source_ip.s_addr, 4) != 0)
            continue;

        printf("\nARP request detected!\n");

        display_arp_packet(
            buffer + sizeof(struct ethhdr),
            (size_t)packet_size - sizeof(struct ethhdr)
        );
    }

    close(sockfd);

    printf("\nExiting program...\n");

    return (0);
}

