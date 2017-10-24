#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define BUFSIZE 512

const uint32_t _IN_LOGIN = 0;
const uint32_t _IN_LOGOUT = 1;
const uint32_t _IN_JOIN = 2;
const uint32_t _IN_LEAVE = 3;
const uint32_t _IN_SAY = 4;
const uint32_t _IN_LIST = 5;
const uint32_t _IN_WHO = 6;
const uint32_t _IN_LIVE = 7;
const uint32_t _IN_ERROR = 99;

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
	char in_buf[BUFSIZE];
	char out_buf[BUFSIZE];
	char ENTER_CHAT[] = "ENTER";

	memset(buf, 0, BUFSIZE);
	memset(in_buf, 0, BUFSIZE);
	memset(out_buf, 0, BUFSIZE);

	resolve_host();

	/* send the message to the server */
	serverlen = sizeof(serveraddr);
	memcpy(out_buf, &_IN_LOGIN, sizeof(_IN_LOGIN));
	n = sendto(sockfd, out_buf, 4, 0, (struct sockaddr *)&serveraddr, serverlen);
	if (n < 0) 
		error("ERROR in sendto");
     
	n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
	if (n < 0) 
		error("ERROR in recvfrom");
	printf("Server requested to use port# %s\n", buf);
	portno = atoi(buf);
	serveraddr.sin_port = htons(portno);

	n = sendto(sockfd, out_buf, 4, 0, (struct sockaddr *)&serveraddr, serverlen);
        if (n < 0)
                error("ERROR in sendto");


	while(1){
		memset(buf, 0, BUFSIZE);
		memset(in_buf, 0, BUFSIZE);
		memset(out_buf, 0, BUFSIZE);

		printf("Please enter msg: ");
		fgets(buf, BUFSIZE, stdin);

		if(memcmp(buf, "EXIT", 4) == 0 || memcmp(buf, "KILL", 4) == 0){
			memcpy(out_buf, &_IN_LEAVE, 4);
			n = sendto(sockfd, out_buf, 4, 0, (struct sockaddr *)&serveraddr, serverlen);
			if(n < 0)
				error("ERROR: sendto failed");

                        puts("Closing Connection");
                        break;
		}else{
			memcpy(out_buf, &_IN_SAY, 4);
			memcpy(&out_buf[4], buf, BUFSIZE-4);

			n = sendto(sockfd, out_buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, serverlen);
			if(n < 0)
				error("ERROR: sendto failed");

			n = recvfrom(sockfd, in_buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
                        printf("Received msg:\t%s\n", in_buf);

			//if(memcmp(buf, "EXIT", 4) == 0 || memcmp(buf, "KILL", 4) == 0){
			//	puts("Closing Connection");
			//	break;
		//}else if(memcmp(buf, "hello", 5) == 0){ /*For testing, remove when done*/
		//	n = recvfrom(sockfd, in_buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
		//	printf("Received msg:\t%s\n", in_buf);
		}
	}

	close(sockfd);
	return;
}

int main(int argc, char **argv) {

    	/* check command line arguments */
	if (argc != 3) {
		hostname = DEFAULT_HOST;
		portno = DEFAULT_PORT;
	}else{
		hostname = argv[1];
		portno = atoi(argv[2]);
	}

	init_server_connection();

	return 0;
}
