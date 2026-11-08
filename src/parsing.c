#include "ft_malcolm.h"

int parse_arguments(int argc, char **argv, t_data *data)
{
    if (!argv || !data || argc != 5)
        return (0);

    if (!parse_ip(argv[1], &data->source_ip))
    {
        printf("ft_malcolm: invalid source IP address: (%s)\n",
            argv[1]);
        return (0);
    }

    if (!parse_mac(argv[2], data->source_mac))
    {
        printf("ft_malcolm: invalid source MAC address: (%s)\n",
            argv[2]);
        return (0);
    }

    if (!parse_ip(argv[3], &data->target_ip))
    {
        printf("ft_malcolm: invalid target IP address: (%s)\n",
            argv[3]);
        return (0);
    }

    if (!parse_mac(argv[4], data->target_mac))
    {
        printf("ft_malcolm: invalid target MAC address: (%s)\n",
            argv[4]);
        return (0);
    }

    return (1);
}

