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
#define MAXCLIENTNUM 100

char ENTER_CHAT[] = "ENTER";
char EXIT_CHAT[] = "EXIT";

struct chat_protocol{
	unsigned int pkt_type;
	unsigned int pkt_len;
	unsigned int msg_len;
};

struct channel{
	char name[64];			//name of channel
	int portno;			//port number assigned to channel
	char portstr[MAXUINTLEN];
	pid_t pid;			//id of proc assigned to channel
	struct user **users;		//array of pointers to user structs. keeps track of connected clients in channel
	unsigned int num_users;
};

struct user{
	char uname[64];
	unsigned int id;
	struct sockaddr_in *clientaddr;
	struct hostent *hostp;		//client host info
	char *hostaddrp;		//dotted decimal host addr str
};

struct channel_MGR{
	unsigned int size;
	struct channel **channels;	//commons channel is always array index 0
};

struct channel *this_channel;
struct channel **channel_arr;
struct sockaddr_in **connected_clients;
struct sockaddr_in clientaddr;
int clientlen;
fd_set read_fds, write_fds;

pid_t pid;
char logging_msg[128];

void error(char *msg){
	perror(msg);
	exit(1);
}

void debug(char *msg){
	printf("[*] DEBUG (%d):\t\t%s\n", pid, msg);
	return;
}

void server_log(char *msg){
	printf("[*] SERVER-LOG (%d):\t%s\n", pid, msg);
	return;
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

char * resolve_client(){
	int n;
	char *hostaddrp;
	char *hostaddrp_copy;
	/*
	*Copy result of inet_ntoa() or it will be lost. From man pages:
	*The string is returned in a statically allocated buffer, which subsequent calls will overwrite.
	*/
	hostaddrp = inet_ntoa(clientaddr.sin_addr);
	if (hostaddrp == NULL) //might want to just return null here instead of exiting the process
		error("ERROR on inet_ntoa\n");

	n = strlen(hostaddrp);
	if(n < 1)
		return NULL;
	hostaddrp_copy = (char *)malloc(n+1);
	memset(hostaddrp_copy, 0, n+1);
	memcpy(hostaddrp_copy, hostaddrp, n);
	if(strlen(hostaddrp_copy) != n){
		debug("resolve_client found un-equal hostaddr strlen's");
		return NULL;
	}

	return hostaddrp_copy;
}

int user_lookup(char *addr){
	/*
	* Returns index of user struct * if addr is found
	* returns -1 if user is not found
	*/
	int i;
	size_t n;
	struct channel *ch = this_channel;

	if(ch->num_users < 1)
		return -1;

	n = strlen(addr);
	if(n > 0){
		for(i=0; i<ch->num_users; i++){
			if(!strncmp(ch->users[i]->hostaddrp, addr, n))
				return i;
		}
	}

	return -1;
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

char * accept_input_blk(int sockfd){
	char *msg;
	int n;

	msg = (char *)malloc(BUFSIZE+1);
	if(!msg)
		error("ERROR: failed to malloc space for client input");

	memset(msg, 0, BUFSIZE+1);
	memset(&clientaddr, 0, sizeof(clientaddr));

	n = recvfrom(sockfd, msg, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
	if(n < 0)
		error("ERROR: recvfrom returned invalid message length");

	//sprintf(logging_msg, "received new message: %s\nMessage length: %d", msg, n); /*Causes segfault, not sure why.*/
	//server_log(logging_msg);
	printf("[*] SERVER-LOG (%d):\treceived new message: %s\n", pid, msg);

	/*Resolve ip addr of client and check if ip exists in connected users*/
	char *hostaddrp = resolve_client();
	//sprintf("resolved client address: %s", hostaddrp);
	//server_log(logging_msg);
	printf("[*] SERVER-LOG (%d):\tresolved client address: %s\n", pid, hostaddrp);
	if(user_lookup(hostaddrp) < 0){
		if(memcmp(msg, "CONNECT", 7) == 0)
			return msg;
		server_log("user not found");
		//Send error message to client saying login required
	}

	return msg;
}

void start_channel(int sfd, struct channel *ch){
	char *msg, userhost_addr;
	int sockfd = sfd;
	int i;
	struct user *new_user;

	
	this_channel = ch;
	this_channel->num_users = 0;
	this_channel->users = malloc(MAXCLIENTNUM * sizeof(struct user*));
	if(!this_channel->users)
		error("ERROR: start_channel() failed to malloc space for users");

	for(i=0; i<MAXCLIENTNUM; i++){
		this_channel->users[i] = NULL;	
	}

	printf("num_users: %d\n", this_channel->num_users);
	if(sockfd < 0)
		error("ERROR: start_channel() received bad sockfd");

	while(1){
		msg = accept_input_blk(sockfd);
		if(memcmp(msg, "CONNECT", 7) == 0){
			free(msg);
			server_log("Client requested to join channel");

			/*Allocate user struct for new client*/
			this_channel->users[this_channel->num_users] = malloc(sizeof(struct user));
			if(!this_channel->users[this_channel->num_users])
				error("ERROR: start_channel() failed to malloc space for new user");

			new_user = this_channel->users[this_channel->num_users];
			this_channel->num_users++;

			/*Allocate sockaddr_in clientaddr struct for new client*/
			new_user->clientaddr = malloc(sizeof(struct sockaddr_in));
			if(!new_user->clientaddr)
				error("ERROR: start_channel() failed to malloc space for new user clientaddr");

			memset(new_user->clientaddr, 0, sizeof(struct sockaddr_in));
			memcpy(new_user->clientaddr, &clientaddr, sizeof(struct sockaddr_in));

			new_user->hostaddrp = resolve_client();
			if(new_user->hostaddrp == NULL)
				debug("resolve_client returned null hostaddrp");

			server_log("Client added to channel");
			//this_channel->num_users--;
			continue;
		}
		else if(memcmp(msg, "KILL", 4) == 0){
			free(msg);
			server_log("Client requested to kill channel connection");
			break;
		}
		else if(memcmp(msg, "EXIT", 4) == 0){
			free(msg);
			printf("SERVER-LOG: Client is leaving channel\n");
			continue;
		}
		printf("SERVER-LOG: Received new message: %s\n", msg);
		free(msg);	
	}

	i=0;
	while(this_channel->users[i]){
		if(this_channel->users[i]->clientaddr)
			free(this_channel->users[i]->clientaddr);
		if(this_channel->users[i]->hostaddrp)
			free(this_channel->users[i]->hostaddrp);

		free(this_channel->users[i]);
		i++;
	}
	if(i != this_channel->num_users)
		debug("found mismatch between free'd user structs and num_users");

	free(this_channel->users);

	close(sockfd);
	exit(0);
}

struct channel *create_channel(char *name, int p){
	int sockfd, serverlen;
	//pid_t pid;
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

void new_connection(int sfd, struct channel* ch){
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
	
	n = sendto(sockfd, ch->portstr, strlen(ch->portstr), 0, (struct sockaddr *)&clientaddr, clientlen);
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
	struct channel_MGR *ch_mgr;

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
	this_channel = 0;

	/*
	*Initialize Channel Manager struct and create Commons channel
	*/
	ch_mgr = (struct channel_MGR*)malloc(sizeof(struct channel_MGR*));
	ch_mgr->size = 0;
	ch_mgr->channels = malloc(256 * (sizeof(struct channel*)));
	ch_mgr->channels[0] = create_channel("Commons", 4446);
	ch_mgr->size++;

	while(1) {
		//msg = accept_input_blk(sockfd);
		msg = (char *)malloc(BUFSIZE+1);
		if(!msg)
			error("ERROR: failed to malloc space for client input");

		memset(msg, 0, BUFSIZE+1);
		memset(&clientaddr, 0, sizeof(clientaddr));

		n = recvfrom(sockfd, msg, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if(n < 0)
			error("ERROR: recvfrom returned invalid message length");

		if(!memcmp(ENTER_CHAT, msg, 5))
			new_connection(sockfd, ch_mgr->channels[0]);

		free(msg);
		memset(&clientaddr, 0, clientlen);
	}

	return 0;
}





