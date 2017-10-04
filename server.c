#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 512

char ENTER_CHAT[] = "enter";
struct sockaddr_in clientaddr;
int clientlen;

void error(char *msg) {
	perror(msg);
	exit(1);
}

void handle_connection(){
	int sockfd, portno, optval;
	struct sockaddr_in serveraddr;

	portno = 0;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		error("ERROR: failed to open socket");
	}

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));
	memset((void *)&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	/*Bind parent socket with port*/

	if(bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
		error("ERROR: failed to bind socket and port");

	puts("CHILD: Successfully bound to new socket");
	close(sockfd);
	return;

}

void new_connection(int sockfd){
	char buf[BUFSIZE];
	struct hostent *hostp;
	char * hostaddrp;
	ssize_t n;
	pid_t pid;

	puts("CHILD: Handling new connection");

	hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
	if (hostp == NULL)
		error("ERROR on gethostbyaddr");

	hostaddrp = inet_ntoa(clientaddr.sin_addr);
	if (hostaddrp == NULL)
		error("ERROR on inet_ntoa\n");

	printf("server received chat request from %s (%s)\n", hostp->h_name, hostaddrp);
	//printf("server received %d/%d bytes: %s\n", strlen(buf), n, buf);

	
	
	pid = fork();
	if(pid < 0)
		error("ERROR: fork failed");

	if(pid == 0){
		close(sockfd);
		handle_connection();
		exit(1);
	}else{
		return;
	}

}

int main(int argc, char** argv) {
	char buf[BUFSIZE];
	int sockfd, newsockfd, portno, optval, pid, n;
	struct sockaddr_in serveraddr;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	portno = atoi(argv[1]);
	if(portno < 1) {
		error("ERROR: received invalid port number");
	}

	/*Create parent socket*/

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		error("ERROR: failed to open socket");
	}

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));
	memset((void *)&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	/*Bind parent socket with port*/

	if(bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
		error("ERROR: failed to bind socket and port");

	puts("SERVER: new listening on socket");
	clientlen = sizeof(clientaddr);

	while(1) {
		memset(buf, 0, BUFSIZE);	

		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if(n < 0)
                	error("ERROR: recvfrom returned invalid message length");

		printf("Received new message: %s\nMessage length: %d\n", buf, n);
		printf("Strlen of ENTER_CHAT: %d\nStrlen of message: %d\n", strlen(ENTER_CHAT), strlen(buf));

		if (memcmp(ENTER_CHAT, buf, 5) == 0){
			new_connection(sockfd);
		}
		/*
		hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
		if (hostp == NULL)
			error("ERROR on gethostbyaddr");

		hostaddrp = inet_ntoa(clientaddr.sin_addr);
		if (hostaddrp == NULL)
			error("ERROR on inet_ntoa\n");

		printf("server received datagram from %s (%s)\n", hostp->h_name, hostaddrp);
		printf("server received %d/%d bytes: %s\n", strlen(buf), n, buf);

		pid = fork();
		if(pid < 0)
			error("ERROR: fork failed");

		if(pid == 0){
			close(sockfd);
			handle_connection(newsockfd);
			exit(1);
		}else{
			close(newsockfd);
		}
		*/

	}
	return 0;
}





