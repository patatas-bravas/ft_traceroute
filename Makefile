NAME = ft_traceroute
CC = gcc 
CFLAGS = -g3 -Wall -Wextra -Werror -Wshadow -I$(DIR_INCLUDE) -std=gnu23
LDFLAGS = -lm -g3 

DIR_INCLUDE = include

DIR_SRC = src
FILE_SRC = main.c

DIR_OBJ = obj
FILE_OBJ = $(FILE_SRC:.c=.o)
OBJS = $(addprefix $(DIR_OBJ)/, $(FILE_OBJ))

all: $(NAME)

test: $(NAME)
	sudo ./$(NAME) www.google.com

$(NAME): $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

$(DIR_OBJ)/%.o: $(DIR_SRC)/%.c | $(DIR_OBJ)
	$(CC) $< $(CFLAGS) -c -o $@

$(DIR_OBJ):
	mkdir $@

clean:
	rm -rf $(DIR_OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all test clean fclean re
