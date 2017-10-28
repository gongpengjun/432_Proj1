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
#define MSGSIZE 132
#define NAMELEN 32
#define TEXTLEN 64

const uint32_t _IN_LOGIN = 0;
const uint32_t _IN_LOGOUT = 1;
const uint32_t _IN_JOIN = 2;
const uint32_t _IN_LEAVE = 3;
const uint32_t _IN_SAY = 4;
const uint32_t _IN_LIST = 5;
const uint32_t _IN_WHO = 6;
const uint32_t _IN_LIVE = 7;
const uint32_t _IN_ERROR = 99;

struct __attribute__((__packed__)) _REQ_LOGIN{
	uint32_t type_id;
	char user_name[NAMELEN];
};

struct __attribute__((__packed__)) _REQ_LOGOUT{
	uint32_t type_id;
};

struct __attribute__((__packed__)) _REQ_JOIN{
	uint32_t type_id;
	char channel_name[NAMELEN];
};

struct __attribute__((__packed__)) _REQ_LEAVE{
	uint32_t type_id;
	char channel_name[NAMELEN];
};

struct __attribute__((__packed__)) _REQ_SAY{
	uint32_t type_id;
	char channel_name[NAMELEN];
	char user_name[NAMELEN];
	char text_field[TEXTLEN];
};

struct __attribute__((__packed__)) _REQ_LIST{
	uint32_t type_id;
};

struct __attribute__((__packed__)) _REQ_WHO{
	uint32_t type_id;
	char channel_name[NAMELEN];
};

struct __attribute__((__packed__)) _REQ_LIVE{
	uint32_t type_id;
};

struct __attribute__((__packed__)) _REQ_NEW{
	char data[MSGSIZE];
	int size;
	char *hostaddrp;
	struct sockaddr_in clientaddr;
	int clientlen;
};

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
	char uname[NAMELEN];
	unsigned int id;
	struct sockaddr_in clientaddr;
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
char *hostaddrp;
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
	memset(logging_msg, 0, 128);
	return;
}

void server_log(char *msg){
	printf("[*] SERVER-LOG (%d):\t%s\n", pid, msg);
	memset(logging_msg, 0, 128);
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

char * resolve_client(struct sockaddr_in *clientaddr){
	int n;
	char *hostaddrp;
	char *hostaddrp_copy;
	/*
	*Copy result of inet_ntoa() or it will be lost. From man pages:
	*The string is returned in a statically allocated buffer, which subsequent calls will overwrite.
	*/
	hostaddrp = inet_ntoa(clientaddr->sin_addr);
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

int user_lookup(char *addr, char *uname){
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
			if(!strncmp(ch->users[i]->hostaddrp, addr, n)){
				if(!uname)
					return i;
				if(!memcmp(ch->users[i]->uname, uname, NAMELEN))
					return i;
			}
		}
	}

	return -1;
}

struct _REQ_NEW * accept_input_blk(int sockfd){
	struct _REQ_NEW * msg;
	int n;

	msg = malloc(sizeof(struct _REQ_NEW));
	if(!msg)
		error("ERROR: failed to malloc space for client input");

	memset(msg, 0, sizeof(struct _REQ_NEW));
	msg->clientlen = sizeof(msg->clientaddr);
	memset(&msg->clientaddr, 0, msg->clientlen);

	msg->size = recvfrom(sockfd, msg->data, MSGSIZE, 0, (struct sockaddr *)&msg->clientaddr, &msg->clientlen);
	printf("Request size: %d\n", msg->size);
	if(msg->size < 0)
		error("ERROR: recvfrom returned invalid message length");

	/*Resolve ip addr of client and check if ip exists in connected users*/
	msg->hostaddrp = resolve_client(&msg->clientaddr);
	snprintf(logging_msg, 128, "resolved client address: %s", msg->hostaddrp);
	server_log(logging_msg);

	return msg;
}

int client_logout(int index){
	int i = index;
	struct user *client;

	client = this_channel->users[i];
	if(client){
		snprintf(logging_msg, 128, "Logging out client:\nUsername: %s\nAddress: %s", client->uname, client->hostaddrp);
		server_log(logging_msg);
		free(client);
	}

	while(i < this_channel->num_users){
		this_channel->users[i] = this_channel->users[i+1];
		i++;
	}

	if(this_channel->num_users > 0)
		this_channel->num_users--;

	return 0;
}

int client_login(struct _REQ_NEW *req, char *uname){
	/*
	* Create and fill new user struct and add it to the channel users list 
	*/
	int n;
	struct user *new_user;

	/*Allocate user struct for new client*/
	this_channel->users[this_channel->num_users] = malloc(sizeof(struct user));
	if(!this_channel->users[this_channel->num_users])
		error("ERROR: start_channel() failed to malloc space for new user");

	new_user = this_channel->users[this_channel->num_users];
	this_channel->num_users++;

	memset(new_user, 0, sizeof(struct user));

	memcpy(&new_user->uname, uname, NAMELEN);
	memcpy(&new_user->clientaddr, &req->clientaddr, req->clientlen);
	if(req->hostaddrp == NULL){
		debug("received request with NULL hostaddrp");
		return -1;
	}
	new_user->hostaddrp = req->hostaddrp;
	snprintf(logging_msg, 128, "Client successfully logged in:\nUsername: %s\nAddress: %s", new_user->uname, new_user->hostaddrp);
	server_log(logging_msg);

	return 0;
}

uint32_t handle_request(struct _REQ_NEW * req){
	/**/
	char msg[MSGSIZE+4]; //4 extra bytes are used for null-byte padding and 64bit alignment
	uint32_t type_id = 0;
	int n;
	
	memset(msg, 0, MSGSIZE+4);
	memcpy(&type_id, req->data, 4);

	if(type_id > 7 || type_id < 0){
		snprintf(logging_msg, 128, "received invalid type_id: %d (0x%08x)\n", type_id, type_id);
		server_log(logging_msg);
		return _IN_ERROR;
	}
	
	snprintf(logging_msg, 128, "type_id: %d (0x%08x)\n", type_id, type_id);
	server_log(logging_msg);

	if(type_id == _IN_LOGIN){
		server_log("Type: Login");
		server_log("Client requested to login to channel");
		if(req->size > (NAMELEN+sizeof(uint32_t)) || req->size <= sizeof(uint32_t)){
			server_log("Login request has invalid size");
			return(_IN_ERROR + _IN_LOGIN);
		}

		memcpy(msg, &req->data[4], NAMELEN);
		if(user_lookup(req->hostaddrp, msg) < 0){
                	client_login(req, msg);
		}else{
			debug("Login request received from already authenticated user");
		}

		return _IN_LOGIN;

	}else if(type_id == _IN_LOGOUT){
                server_log("Type: Logout");
		/*
		* Should implement some form of logout verification, or else another user 
		* could forge source ip and logout other users.
		*/
		n = user_lookup(req->hostaddrp, NULL);
		if(n != -1){
			client_logout(n);
		}else{
			server_log("Received logout request from non-authenticated user");
			return(_IN_ERROR + _IN_LOGOUT);
		}

		return _IN_LOGOUT;	

	}else if(type_id == _IN_JOIN){
                server_log("Type: Join");
		return _IN_JOIN;
		//break;

	}else if(type_id == _IN_LEAVE){
                server_log("Type: Leave");
		server_log("client requested to kill channel connection");
		return _IN_LEAVE;

	}else if(type_id == _IN_SAY){
		server_log("Type: Say");
		if(req->size > (4 + NAMELEN + TEXTLEN)){
			server_log("Say request has invalid size");
			return(_IN_ERROR + _IN_SAY);
		}
		
		return _IN_SAY;

	}else if(type_id == _IN_LIST){
                server_log("Type: List");
		return _IN_LIST;

	}else if(type_id == _IN_WHO){
                server_log("Type: Who");
		return _IN_WHO;

	}else if(type_id == _IN_LIVE){
                server_log("Type: Keep Alive");
		return _IN_LIVE;

	}else{
		debug("ERROR: server received bad message type");
	}

	return _IN_ERROR;
}

void start_channel(int sfd, struct channel *ch){
	struct _REQ_NEW * msg;
	char *userhost_addr;
	uint32_t msg_type;
	int sockfd = sfd;
	int i, n;

	this_channel = ch;
	this_channel->num_users = 0;
	this_channel->users = malloc(MAXCLIENTNUM * sizeof(struct user*));
	if(!this_channel->users)
		error("ERROR: start_channel() failed to malloc space for users");

	for(i=0; i<MAXCLIENTNUM; i++){
		this_channel->users[i] = NULL;	
	}
	
	if(sockfd < 0)
		error("ERROR: start_channel() received bad sockfd");

	while(1){
		msg = accept_input_blk(sockfd);
		msg_type = handle_request(msg);
		if(msg_type == _IN_ERROR || msg_type == (msg_type + _IN_ERROR)){
			debug("Server received invalid request");
			free(msg);
			continue;
		}

		if(msg_type == _IN_LOGOUT){
			debug("Closing channel and exiting child process");
			free(msg);
			break;
		}else if(msg_type == _IN_SAY){
			i=0;
			while(this_channel->users[i]){
				snprintf(logging_msg, 128, "sending message to (%s)", this_channel->users[i]->hostaddrp);
				server_log(logging_msg);
				n = sendto(sockfd, msg->data, MSGSIZE, 0, (struct sockaddr *)&this_channel->users[i]->clientaddr, msg->clientlen);
				if(n < 0)
					debug("failed to send message to client");
				i++;
			}	
		}

		free(msg);	
	}

	i=0;
	while(this_channel->users[i]){
		//if(&this_channel->users[i]->clientaddr)
		//	free(this_channel->users[i]->clientaddr);
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
	/*
	* Bind to new socket and fork process.
	* The child process will then be incharge of the new socket,
	* where all traffic on channel "name" will be handled
	*/
	int sockfd, serverlen;
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

	printf("[*] SERVER-LOG:  \treceived chat request from %s (%s)\n", hostp->h_name, hostaddrp);
	
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
	uint32_t msg_type;
	int sockfd, portno, debug_portno, optval, n, req_size;
	struct sockaddr_in serveraddr;
	struct channel_MGR *ch_mgr;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}
	if (argc == 3){
		debug_portno = atoi(argv[2]);
		if(debug_portno < 1)
			error("ERROR: received invalid debug port number");
	}else{
		debug_portno = 0;
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
	ch_mgr->channels[0] = create_channel("Commons", debug_portno);
	ch_mgr->size++;

	req_size = sizeof(struct _REQ_LOGIN);
	struct _REQ_LOGIN * _LOGIN = malloc(req_size);
	if(!_LOGIN)
		error("ERROR: main failed to allocate space for _LOGIN struct");

	while(1) {
		memset(_LOGIN, 0, req_size);
		memset(&clientaddr, 0, sizeof(clientaddr));

		n = recvfrom(sockfd, _LOGIN, req_size, 0, (struct sockaddr *)&clientaddr, &clientlen);
		if(n < 0)
			error("ERROR: recvfrom returned invalid message length");

		if(_LOGIN->type_id == _IN_LOGIN)
			new_connection(sockfd, ch_mgr->channels[0]);
	}

	return 0;
}





