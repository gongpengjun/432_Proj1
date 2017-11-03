CC=gcc

# CFLAGS=-Wall -W -g -Werror -pthread
CFLAGS=-g -pthread

all: server client

client: client.c raw.c
	$(CC) client.c raw.c $(CFLAGS) -o client

server: server.c 
	$(CC) server.c $(CFLAGS) -o server

clean:
	rm -f server client *.o
