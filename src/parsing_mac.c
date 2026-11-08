#include "ft_malcolm.h"

int parse_mac(const char *mac, unsigned char result[6])
{
    unsigned int values[6];
    char extra;

    if (!mac || !result)
        return (0);

    if (sscanf(mac, "%2x:%2x:%2x:%2x:%2x:%2x%c",
        &values[0],
        &values[1],
        &values[2],
        &values[3],
        &values[4],
        &values[5],
        &extra) != 6)
        return (0);

    for (int i = 0; i < 6; i++)
    {
        if (values[i] > 255)
            return (0);
        result[i] = (unsigned char)values[i];
    }

    return (1);
}

