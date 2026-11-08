#include "ft_malcolm.h"

int parse_ip(const char *ip, struct in_addr *result)
{
    if (!ip || !result)
        return (0);

    if (inet_pton(AF_INET, ip, result) != 1)
        return (0);

    return (1);
}

