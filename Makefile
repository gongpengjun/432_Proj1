CC=gcc

all: server.c client.c
	gcc -o server server.c -lpthread
	gcc -o client client.c -lpthread

server: server.c
	gcc -o server server.c -lpthread

client: client.c
	gcc -o client client.c -lpthread

clean:
	rm server
	rm client
