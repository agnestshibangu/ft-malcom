#include "ft_malcolm.h"
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* Fonction utilitaire pour désactiver l'ARP via ioctl (équivalent de "ip link set dev <name> arp off") */
static int disable_arp_on_interface(const char *interface_name)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
        return (0);

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", interface_name);

    // Récupérer les flags actuels
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1)
    {
        close(sockfd);
        return (0);
    }

    // Ajouter le flag IFF_NOARP (désactive l'ARP)
    ifr.ifr_flags |= IFF_NOARP;

    // Appliquer les nouveaux flags
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1)
    {
        close(sockfd);
        close(sockfd);
        return (0);
    }

    close(sockfd);
    return (1);
}

int find_interface(struct in_addr source_ip, char *interface)
{
    struct ifaddrs *interfaces;
    struct ifaddrs *current;

    if (!interface)
        return (0);

    if (getifaddrs(&interfaces) == -1)
    {
        perror("ft_malcolm: getifaddrs");
        return (0);
    }

    current = interfaces;
    while (current)
    {
        if (current->ifa_addr
            && current->ifa_addr->sa_family == AF_INET)
        {
            struct sockaddr_in *addr;

            addr = (struct sockaddr_in *)current->ifa_addr;

            if (addr->sin_addr.s_addr == source_ip.s_addr)
            {
                snprintf(interface, IFNAMSIZ, "%s", current->ifa_name);
                
                // Désactivation automatique de l'ARP sur l'interface trouvée
                if (!disable_arp_on_interface(current->ifa_name))
                {
                    perror("ft_malcolm: failed to disable ARP");
                    freeifaddrs(interfaces);
                    return (0);
                }

                freeifaddrs(interfaces);
                return (1);
            }
        }
        current = current->ifa_next;
    }

    freeifaddrs(interfaces);
    return (0);
}
