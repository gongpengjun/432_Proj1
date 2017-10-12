#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
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

struct channel{
	char name[64];		//name of channel
	int portno;		//port number assigned to channel
	char portstr[MAXUINTLEN];
	pid_t pid;		//id of proc assigned to channel
};

struct channel *this_channel, *channel_arr;
struct sockaddr_in **connected_clients;
struct sockaddr_in clientaddr;
int clientlen;
fd_set read_fds, write_fds;

void error(char *msg) {
	perror(msg);
	exit(1);
}

void clean_globals(){
	/*
	* Called by recently forked-child to ensure non-essential
	* global vars copied from parent to child are cleared.
	*/
	FD_ZERO(&read_fds);	//redundent but just to be safe
	return;
}

int bind_new_socket(struct sockaddr_in serveraddr, int p) {
	int sockfd, optval, portno, n;

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

char * accept_input(int sockfd){
	/*
	* Uses select() to implement non-blocking reads from socket.
	* Returns pointer to heap-buffer containing client message
	*/
	char *msg;
	int n;

	msg = (char *)malloc(BUFSIZE+1);
	if(!msg)
		error("ERROR: failed to malloc space for client input");

	memset(msg, 0, BUFSIZE+1);

	FD_ZERO(&read_fds);
	FD_SET(sockfd, &read_fds);

	printf("SERVER-LOG: Server is accepting input");
	n = select(sockfd+1, &read_fds, &write_fds, 0, 0);
	if(n < 0)
		error("ERROR: in select return value");

	if(FD_ISSET(sockfd, &read_fds)){

		n = recvfrom(sockfd, msg, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if(n < 0)
                	error("ERROR: recvfrom returned invalid message length");

		printf("SERVER-LOG: Received new message: %s\nMessage length: %d\n", msg, n);
		FD_CLR(sockfd, &read_fds);
	}else{
		error("ERROR: FD_ISSET returned non-zero value");
	}

	return msg;
}

void start_channel(int sfd, struct channel *ch){
	char *msg;
	int sockfd = sfd;

	this_channel = ch;
	if(sockfd < 0)
		error("ERROR: start_channel() received bad sockfd");

	while(1){
		msg = accept_input(sockfd);
		if(memcmp(msg, "EXIT", 4) == 0){
			free(msg);
			printf("SERVER-LOG: Client requested to close connection\n");
			break;
		}
		printf("SERVER-LOG: Received new message: %s\n", msg);
		free(msg);	
	}

	close(sockfd);
	return;
}

struct channel *create_channel(char *name, int p){
	int sockfd, serverlen;
	pid_t pid;
	struct sockaddr_in serveraddr;
	int portno = p;

	struct channel *ch = (struct channel*)malloc(sizeof(struct channel));
	if(!ch)
		error("ERROR: malloc failed to allocate channel struct");

	memset(ch->name, 0, 64);
	strncpy(ch->name, name, 63);

	sockfd = bind_new_socket(serveraddr, portno);
	serverlen = sizeof(serveraddr);

	/*Resolve OS-assigned port number*/
	if(getsockname(sockfd, (struct sockaddr *)&serveraddr, &serverlen))
		error("ERROR: getsockname failed");
	portno = ntohs(serveraddr.sin_port);
	ch->portno = portno;
	snprintf(ch->portstr, MAXUINTLEN, "%d", portno);

	pid = fork();
	if(pid < 0)
		error("ERROR: fork failed in create_channel()");
	if(pid == 0){	
		ch->pid = 0;
		printf("CHILD: Channel %s info:\nPORTNO %d\nPORTSTR %s\nPID %d\n", ch->name, ch->portno, ch->portstr, ch->pid);
		start_channel(sockfd, ch);
	}else{
		ch->pid = pid;
		printf("PARENT: Channel %s info:\nPORTNO %d\nPORTSTR %s\nPID %d\n", ch->name, ch->portno, ch->portstr, ch->pid);
		return ch;
	}

}

void new_connection(int sfd){
	struct hostent *hostp;
	char * hostaddrp;
	ssize_t n;
	int sockfd = sfd;

	hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
	if (hostp == NULL)
		error("ERROR on gethostbyaddr");

	hostaddrp = inet_ntoa(clientaddr.sin_addr);
	if (hostaddrp == NULL)
		error("ERROR on inet_ntoa\n");

	printf("SERVER-LOG: Received chat request from %s (%s)\n", hostp->h_name, hostaddrp);
	
	n = sendto(sockfd, channel_arr->portstr, strlen(channel_arr->portstr), 0, (struct sockaddr *)&clientaddr, clientlen);
	if (n < 0)
		error("ERROR in sendto");

	/*
	*Once sighandler is implemented, add check here
	*Verify that client successfully connected to child
	*/

	return;
}

int main(int argc, char** argv) {
	char *msg;
	int sockfd, portno, optval, n;
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
	puts("SERVER-LOG: Server is now listening");

	clientlen = sizeof(clientaddr);
	channel_arr = create_channel("Commons", 0);

	while(1) {
		msg = accept_input(sockfd);
		if(!memcmp(ENTER_CHAT, msg, 5))
			new_connection(sockfd);

		free(msg);
		memset(&clientaddr, 0, clientlen);
	}

	return 0;
}





