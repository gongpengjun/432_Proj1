#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <limits.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 512
#define MAXUINTLEN 20

char ENTER_CHAT[] = "ENTER";
char EXIT_CHAT[] = "EXIT";

struct chat_protocol{
	unsigned int pkt_type;
	unsigned int pkt_len;
	unsigned int msg_len;
};

struct sockaddr_in clientaddr;
int clientlen;

void error(char *msg) {
	perror(msg);
	exit(1);
}

int bind_new_socket(struct sockaddr_in serveraddr, int p) {
	int sockfd, optval, portno;

	portno = p;
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

	return sockfd;
}

void establish_connection(){
	char buf[BUFSIZE];
	char portstr[MAXUINTLEN];
	int sockfd, portno, optval, serverlen, n;
	struct sockaddr_in serveraddr;

	memset(buf, 0, BUFSIZE);
	memset(portstr, 0, MAXUINTLEN);
	portno = 0;

	sockfd = bind_new_socket(serveraddr, portno);
	serverlen = sizeof(serveraddr);
	if(getsockname(sockfd, (struct sockaddr *)&serveraddr, &serverlen))
		error("ERROR: getsockname failed");
	portno = ntohs(serveraddr.sin_port);
	snprintf(portstr, MAXUINTLEN, "%d", portno);

	printf("CHILD: Bound to port #%d\nConverted to string: %s\n", portno, portstr);

	n = sendto(sockfd, portstr, strlen(portstr), 0, (struct sockaddr *)&clientaddr, clientlen);
	if (n < 0) 
		error("ERROR in sendto");

	while(1){
        	n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if(n < 0)
			error("ERROR: recvfrom returned invalid message length");
		if(memcmp(buf, "EXIT", 4) == 0){
			printf("SERVER-LOG: Client requested to close connection\n");
			break;
		}
		printf("SERVER-LOG: Received new message: %s\nMessage length: %d\n", buf, n);
		memset(buf, 0, BUFSIZE);
	}

	close(sockfd);
	return;

}

void new_connection(){
	struct hostent *hostp;
	char * hostaddrp;
	ssize_t n;
	int newsockfd;
	pid_t pid;	

	hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
	if (hostp == NULL)
		error("ERROR on gethostbyaddr");

	hostaddrp = inet_ntoa(clientaddr.sin_addr);
	if (hostaddrp == NULL)
		error("ERROR on inet_ntoa\n");

	printf("SERVER-LOG: Received chat request from %s (%s)\n", hostp->h_name, hostaddrp);

	pid = fork();
	if(pid < 0)
		error("ERROR: fork failed");

	if(pid == 0){
		establish_connection();
		exit(1);
	}else{
		return;
	}

}

int main(int argc, char** argv) {
	char buf[BUFSIZE];
	int sockfd, newsockfd, portno, optval, n;
	struct sockaddr_in serveraddr;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	portno = atoi(argv[1]);
	if(portno < 1) {
		error("ERROR: received invalid port number");
	}

	sockfd = bind_new_socket(serveraddr, portno);

	puts("SERVER-LOG: now listening on socket");
	clientlen = sizeof(clientaddr);

	while(1) {
		memset(buf, 0, BUFSIZE);	

		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if(n < 0)
                	error("ERROR: recvfrom returned invalid message length");

		printf("SERVER-LOG: Received new message: %s\nMessage length: %d\n", buf, n);

		if (memcmp(ENTER_CHAT, buf, 5) == 0){
			new_connection();
		}
		memset(&clientaddr, 0, clientlen);
	}

	return 0;
}





