CC=gcc

all: server.c client.c
	gcc -o server server.c
	gcc -o client client.c -lpthread

server: server.c
	gcc -o server server.c

client: client.c
	gcc -o client client.c -lpthread

clean:
	rm server
	rm client
