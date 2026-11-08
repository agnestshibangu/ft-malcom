#ifndef FT_MALCOLM_H
# define FT_MALCOLM_H

# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <stdint.h>
# include <signal.h>
# include <arpa/inet.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <net/if.h>

typedef struct s_data
{
    struct in_addr source_ip;
    struct in_addr target_ip;
    unsigned char source_mac[6];
    unsigned char target_mac[6];
    char interface[IFNAMSIZ];
}   t_data;

int     find_interface(struct in_addr source_ip, char *interface);
int     parse_arguments(int argc, char **argv, t_data *data);
int     parse_ip(const char *ip, struct in_addr *result);
int     parse_mac(const char *mac, unsigned char result[6]);
void    print_error(const char *message);
void    handle_signal(int signal_number);
void    display_arp_packet(const unsigned char *packet, size_t length);

#endif

