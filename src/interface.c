#include "ft_malcolm.h"
#include <ifaddrs.h>

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
                snprintf(interface, IFNAMSIZ, "%s",
                    current->ifa_name);
                freeifaddrs(interfaces);
                return (1);
            }
        }
        current = current->ifa_next;
    }

    freeifaddrs(interfaces);
    return (0);
}

