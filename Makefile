NAME = ft_malcolm

CC = gcc
CFLAGS = -Wall -Wextra -Werror

INCLUDES = -I includes

SRC = src/main.c \
      src/parsing.c \
      src/parsing_ip.c \
      src/parsing_mac.c \
      src/interface.c \
      src/arp.c \
      src/utils.c

OBJ = $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re

