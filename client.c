#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define BUFSIZE 512

char DEFAULT_HOST[] = "127.0.0.1";
int DEFAULT_PORT = 4444;

int sockfd, portno;
struct sockaddr_in serveraddr;
struct hostent *server;
char *hostname;

void error(char *msg) {
	perror(msg);
	exit(0);
}

void resolve_host() {

	memset((char *)&serveraddr, 0, sizeof(serveraddr));

    	/* create the socket */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");

  	/* get the server's DNS entry */
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host as %s\n", hostname);
		exit(0);
	}

	serveraddr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
	serveraddr.sin_port = htons(portno);
	
	return;
}

void init_server_connection() {
	int n, serverlen;
	char buf[BUFSIZE];
	char ENTER_CHAT[] = "enter";

	memset(buf, 0, BUFSIZE);

	resolve_host();

	/* send the message to the server */
	serverlen = sizeof(serveraddr);
	n = sendto(sockfd, ENTER_CHAT, 5, 0, (struct sockaddr *)&serveraddr, serverlen);
	if (n < 0) 
		error("ERROR in sendto");
     
	n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
	if (n < 0) 
		error("ERROR in recvfrom");
	printf("Server requested to use port# %s", buf);
	portno = atoi(buf);
	serveraddr.sin_port = htons(portno);

	memset(buf, 0, BUFSIZE);
	printf("Please enter msg: ");
	fgets(buf, BUFSIZE, stdin);

	n = sendto(sockfd, buf, strlen(buf), 0, (struct sockaddr *)&serveraddr, serverlen);
	if(n<0)
		error("ERROR: sendto failed");

	close(sockfd);
	return;
}

int main(int argc, char **argv) {
	/*
	int sockfd, portno, n;
	int serverlen;
	struct sockaddr_in serveraddr;
	struct hostent *server;
	char *hostname;
	char buf[BUFSIZE];
	*/	

    	/* check command line arguments */
	if (argc != 3) {
		hostname = DEFAULT_HOST;
		portno = DEFAULT_PORT;
	}else{
		hostname = argv[1];
		portno = atoi(argv[2]);
	}

	init_server_connection();

	/*
	memset((char *)&serveraddr, 0, sizeof(serveraddr));
	memset(buf, 0, BUFSIZE);
 
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");
	
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host as %s\n", hostname);
		exit(0);
	}

	serveraddr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
	serveraddr.sin_port = htons(portno);


	serverlen = sizeof(serveraddr);
	n = sendto(sockfd, ENTER_CHAT, 5, 0, (struct sockaddr *)&serveraddr, serverlen);
	if (n < 0) 
		error("ERROR in sendto");
     
	n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
	if (n < 0) 
		error("ERROR in recvfrom");
	printf("Server requested to use port# %s", buf);
	portno = atoi(buf);
	serveraddr.sin_port = htons(portno);

	memset(buf, 0, BUFSIZE);
	printf("Please enter msg: ");
	fgets(buf, BUFSIZE, stdin);

	n = sendto(sockfd, buf, strlen(buf), 0, (struct sockaddr *)&serveraddr, serverlen);
	if(n<0)
		error("ERROR: sendto failed");

	close(sockfd);
	*/
	return 0;
}
