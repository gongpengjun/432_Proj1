#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/shm.h>
#include <errno.h>
#include <semaphore.h>
#include <fcntl.h>

#define BUFSIZE 512
#define MAXUINTLEN 20
#define MAXCLIENTNUM 100
#define MSGSIZE 100
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

struct _REQ_QUEUE{
	struct _REQ_SAY *waiting[128];
	int size;
};

struct channel{
	char name[NAMELEN];		//name of channel. Also, channel name is used as semaphore name
	int portno;			//port number assigned to channel
	char portstr[MAXUINTLEN];
	int sockfd;
	struct sockaddr_in serveraddr;
	sem_t *sem_lock;
	unsigned int sem_value;
	void *shmem;
	pid_t pid;			//id of proc assigned to channel
	struct user **users;		//array of pointers to user structs. keeps track of connected clients in channel
	unsigned int num_users;
};

struct channel_list{
        struct channel *ch;
        struct channel_list *ch_next;
        struct channel_list *ch_prev;
};

struct user{
	char uname[NAMELEN];
	unsigned int id;
	struct channel_list *ch_list;
	struct sockaddr_in clientaddr;
	struct hostent *hostp;		//client host info
	char *hostaddrp;		//dotted decimal host addr str
};

struct AUTHD_CLIENT{
	struct user* user_s;
	struct AUTHD_CLIENT* prev;
	struct AUTHD_CLIENT* next;
};

struct __attribute__((__packed__)) SHMEM_USR_ACTION{
	uint32_t type_id;
	char user_name[NAMELEN];
	char text_field[TEXTLEN];
	struct sockaddr_in clientaddr;
}shmem_user;

struct __attribute__((__packed__)) SHMEM_SAY_ACTION{
	uint32_t type_id;
	char text_field[TEXTLEN];
	struct sockaddr_in clientaddr;
}shmem_say;

struct channel_MGR{
	unsigned int size;
	struct channel **channels;	//commons channel is always array index 0
};

//pthread_t tid;
//pthread_t tid2;
pthread_t tid[3];
pthread_mutex_t lock1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock3 = PTHREAD_MUTEX_INITIALIZER;
struct _REQ_QUEUE * req_Q;
struct _REQ_QUEUE * req_Q_backlog;
struct AUTHD_CLIENT *client_list;
struct channel *this_channel;
struct channel_MGR *ch_mgr;
struct channel **channel_arr;
struct sockaddr_in **connected_clients;
struct sockaddr_in clientaddr;
char *hostaddrp;
int clientlen;
int tmp_sockfd;
int thread_exit;
unsigned int SHMEM_USER_SIZE;
unsigned int SHMEM_SAY_SIZE;
unsigned int SHMEM_STCK_SIZE;

pid_t pid;
char logging_msg[128];

void shmem_enqueue(struct channel *ch);
struct channel *create_channel(char *name, int p);
int handle_leave_request(struct channel *ch, struct user *client);
int handle_join_request(int sfd, struct channel* ch, struct user *client, char *channel_name);
void new_connection(int sfd, struct channel* ch, char * name);
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
	char hostname[1024];
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
	gethostname(hostname, 1023);
	printf("[*] Got hostname: %s\n", hostname);

	return hostaddrp_copy;
}

int add_channel_user(struct user *client, struct channel *ch){
	struct channel_list *next_channel;

	/*Initialize the client's channel list if it NULL*/
	if(!client->ch_list){
		if(!(client->ch_list = malloc(sizeof(struct channel_list)))){
			debug("failed to allocate channel list for user");
			return -1;
		}
		memset(client->ch_list, 0, sizeof(struct channel_list));
		client->ch_list->ch = ch;
		client->ch_list->ch_prev = NULL;
		client->ch_list->ch_next = NULL;
		return 0;
	}

	next_channel = client->ch_list;

	while(next_channel->ch_next){
		if(!next_channel->ch){
			next_channel->ch = ch;
			return 0;
		}
		if(!strncmp(next_channel->ch->name, ch->name, NAMELEN)){
			return 1;
		}
		next_channel = next_channel->ch_next;
	}

	next_channel->ch_next = malloc(sizeof(struct channel_list));
	memset(next_channel->ch_next, 0, sizeof(struct channel_list));
	next_channel->ch_next->ch = ch;
	next_channel->ch_next->ch_next = NULL;
	next_channel->ch_next->ch_prev = next_channel;

	return 0;
}

int remove_channel_user(struct user *client, struct channel *ch){
	struct channel_list *next_channel;

	next_channel = client->ch_list;
	printf("[*] remove_channel_user is starting with client: %s\n", client->uname);
	while(next_channel){
		puts("next_channel iteration");
		if(next_channel->ch == NULL){
			puts("next_channel->ch is NULL");
			break;
		}

		if(!strncmp(next_channel->ch->name, ch->name, NAMELEN)){
			if(next_channel->ch_next != NULL && next_channel->ch_prev != NULL){
				next_channel->ch_next->ch_prev = next_channel->ch_prev;
				next_channel->ch_prev->ch_next = next_channel->ch_next;
				free(next_channel);
			}else if(next_channel->ch_next != NULL){
				next_channel->ch_next->ch_prev = NULL;
				free(next_channel);
			}else if(next_channel->ch_prev != NULL){
				next_channel->ch_prev->ch_next = NULL;
				free(next_channel);
			}else{
				client->ch_list = NULL;
				free(next_channel);	
			}
			server_log("found channel user. proceeding with shmem_enqueue to remove.");
			shmem_user.type_id = _IN_LEAVE;
			memcpy(shmem_user.user_name, client->uname, NAMELEN);
			memcpy(&shmem_user.clientaddr, &client->clientaddr, sizeof(struct sockaddr));
			shmem_enqueue(ch);
			return 1;
		}
		next_channel = next_channel->ch_next;
	}
	return 0;
}

struct AUTHD_CLIENT *client_lookup(char *addr, char *uname){
	struct AUTHD_CLIENT *client;
	int n;

	if(!client_list)
		return NULL;

	client = client_list;
	//puts("In client_lookup");
	while(client){
		if(client->user_s){
			printf("[*] client_lookup: checking client: %s\n", client->user_s->uname);
			n = strlen(addr);
			if(uname && addr){
				if(!memcmp(client->user_s->uname, uname, NAMELEN)){
					if(!strncmp(client->user_s->hostaddrp, addr, n))
						return client;
					else
						return NULL;
				}
			}else if(addr && !uname){
				if(!strncmp(client->user_s->hostaddrp, addr, n))
					return client;
			}else if(!addr && !uname){
				return NULL;
			}
		}else{
			printf("[*] client_lookup: client struct has user_s addr: %p\n", client->user_s);
		}
		client = client->next;
	}
	server_log("Client not found.");
	return NULL;
	/*
	while(client){
		n = strlen(addr);
		if(!strncmp(client->user_s->hostaddrp, addr, n)){
			if(!uname)
				return client;
		}
		if(!memcmp(client->user_s->uname, uname, NAMELEN)){
				return client;
		}
		client = client->prev;
	}
	return NULL;
	*/
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
	if(n < 1){
		debug("user_lookup received invalid user name length");
		return -1;
	}
	for(i=0; i<ch->num_users; i++){
		if(!strncmp(ch->users[i]->hostaddrp, addr, n)){
			if(!uname)
				return i;
			if(!memcmp(ch->users[i]->uname, uname, NAMELEN))
				return i;
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

	memcpy(&clientaddr, &msg->clientaddr, msg->clientlen);
	clientlen = msg->clientlen;
	/*Resolve ip addr of client and check if ip exists in connected users*/
	msg->hostaddrp = resolve_client(&msg->clientaddr);
	snprintf(logging_msg, 128, "resolved client address: %s", msg->hostaddrp);
	server_log(logging_msg);

	return msg;
}

int client_logout(struct AUTHD_CLIENT *client){
	struct user *usr;
	struct channel_list *ch_list;

	int n;
	if(client){
		if(client->prev && client->next){
			puts("Client has next and prev");
			client->next->prev = client->prev;
			client->prev->next = client->next;
		}else if(client->next){
			puts("Client has next");
			client->next->prev = NULL;
		}else if(client->prev){
			puts("Client has prev");
			client->prev->next = NULL;
		}

		/*n = sendto(tmp_sockfd, &_IN_LOGOUT, sizeof(uint32_t), 0, (struct sockaddr *)&client->user_s->clientaddr, sizeof(struct sockaddr));
                if(n < 1)
                        puts("Logout ack failed to send");
                snprintf(logging_msg, 128, "Logging out client:\nUsername: %s\nAddress: %s", client->user_s->uname, client->user_s->hostaddrp);
                server_log(logging_msg);
		*/

		usr = client->user_s;
		if(!usr){
			printf("ERROR: authd client struct has NULL user struct\n");
			return -1;
		}
		ch_list = usr->ch_list;
		while(ch_list){
			printf("[*] client_logout: channel addr -> %p\t user addr -> %p\n", ch_list->ch, usr);
			if(ch_list->ch != NULL){
				//snprintf(logging_msg, 128, "removing user (%s) from channel (%s).", usr->uname, ch_list->ch->name);
				//server_log(logging_msg);
				remove_channel_user(usr, ch_list->ch);
			}
			ch_list = ch_list->ch_next;
		}

		free(client->user_s);
		free(client);
		client_list = NULL;
		return 0;
	}
	return -1;
}

struct AUTHD_CLIENT * client_login(struct _REQ_NEW *req, char *uname){
	int n;
	struct user *new_user;
	struct AUTHD_CLIENT *client;
	struct AUTHD_CLIENT *list_tail;

	if(!(new_user = malloc(sizeof(struct user)))){
		debug("client login failed to allocate space for new_user");
		return NULL;
	}

	if(!(client = malloc(sizeof(struct AUTHD_CLIENT)))){
		debug("client login failed to allocate new client struct");
		return NULL;
	}

	//Zero-out new user struct
	memset(new_user, 0, sizeof(struct user));
	//Zero-out new authd client struct
	memset(client, 0, sizeof(struct AUTHD_CLIENT));
	//Init new user's clientaddr, hostaddr, and user name
        memcpy(&new_user->clientaddr, &req->clientaddr, sizeof(struct sockaddr));
        new_user->hostaddrp = resolve_client(&new_user->clientaddr);
        memcpy(new_user->uname, uname, NAMELEN);

	//If client_list has not been initialized, then init with new authd client struct
	if(!client_list){
		client_list = client;
		client->user_s = new_user;
		return client;
	}
	//Find tail of authd client list
	list_tail = client_list;
	while(list_tail->next){
		printf("client_list has next\n");
		list_tail = list_tail->next;
	}
	//append new authd client struct to tail of list
	list_tail->next = client;
	client->prev = list_tail;
	client->next = NULL;
	/*
	client->prev = client_list;
	client->next = NULL;
	client_list->next = client;

	client->user_s = new_user;
	client_list = client;
	snprintf(logging_msg, 128, "Client successfully logged in:\nUsername: %s\nAddress: %s", new_user->uname, new_user->hostaddrp);
        server_log(logging_msg);
	
	new_user->ch_list = malloc(sizeof(struct channel_list));
	memset(new_user->ch_list, 0, sizeof(struct channel_list));
	new_user->ch_list->ch = NULL; //ch_mgr->channels[0];
	new_user->ch_list->ch_next = NULL;
	new_user->ch_list->ch_prev = NULL;
	*/

	//set new tail authd client struct's user struct to the new user's struct
	client->user_s = new_user;
	printf("[*] Server has logged in User: %s (hostaddr: %s)\n", client->user_s->uname, client->user_s->hostaddrp);
	//server_log("client_login added client");
	return client;
}

int leave_channel(struct SHMEM_USR_ACTION *req){
	struct user * old_user;
	char *hostaddrp;
	char uname[NAMELEN];
	int index, i;
	int retval=0;
	struct channel * ch = this_channel;

	memset(uname, 0, NAMELEN);
	memcpy(uname, req->user_name, NAMELEN);
	hostaddrp = resolve_client(&req->clientaddr);

	pthread_mutex_lock(&lock2);
	index = user_lookup(hostaddrp, uname);
	if(index == -1){	
		server_log("User has not joined or has already left this channel");
		free(hostaddrp);
		retval = -1;
	}else if(index < ch->num_users){
		if(ch->users[index])
			free(ch->users[index]);
		i = 0;
		while(index < this_channel->num_users){
                	this_channel->users[index] = this_channel->users[index+1];
                	index++;
        	}	

        	if(this_channel->num_users > 0)
                	this_channel->num_users--;
		if(this_channel->num_users < 1){
			retval = 1;
			printf("[*] Channel users #: %d\n", this_channel->num_users);
		}

		//printf("[*] Channel users #: %d\n", this_channel->num_users);
		free(hostaddrp);
		server_log("Client has successfully left the channel");
	}
	pthread_mutex_unlock(&lock2);
	return retval;
}

void join_channel(struct SHMEM_USR_ACTION *req){
	struct user * new_user;
	struct channel * ch = this_channel;

	new_user = malloc(sizeof(struct user));
	if(!new_user)
		error("ERROR: join_channel: ");
	memset(new_user, 0, sizeof(struct user));

	memcpy(&new_user->clientaddr, &req->clientaddr, sizeof(struct sockaddr));
	new_user->hostaddrp = resolve_client(&new_user->clientaddr);
	memcpy(new_user->uname, req->user_name, NAMELEN);
	if((user_lookup(new_user->hostaddrp, new_user->uname)) != -1){
		server_log("User has already joined this channel");
		free(new_user->hostaddrp);
		free(new_user);
		return;
	}
	pthread_mutex_lock(&lock2);
	ch->users[ch->num_users] = new_user;
	ch->num_users++;
	pthread_mutex_unlock(&lock2);
	snprintf(logging_msg, 128, "User: %s (%s) has joined the channel.", new_user->uname, new_user->hostaddrp);
	server_log(logging_msg);

	return;
}

void handle_backlog(){
	int i;
	pthread_mutex_lock(&lock1);

	if(req_Q_backlog->size < 1){
		pthread_mutex_unlock(&lock1);
		return;
	}

	i=0;
	while(req_Q_backlog->waiting[i]){
		req_Q->waiting[req_Q->size] = req_Q_backlog->waiting[i];
		req_Q->size++;
		req_Q_backlog->waiting[i] = NULL;
		i++;
	}
	req_Q_backlog->size = 0;

	pthread_mutex_unlock(&lock1);
	return;
}

void *send_requests(void *vargp){
	struct _REQ_SAY * _SAY;
	struct user **clients;
	char outbuf[MSGSIZE];
	int i,j,n;

	while(1){
		if(req_Q->size < 1)
			handle_backlog();

		if(req_Q->size < 1)
			continue;

		for(j=0; j<req_Q->size; j++){
			if(!req_Q->waiting[j])
				continue;

			memset(outbuf, 0, MSGSIZE);
			_SAY = req_Q->waiting[j];
			/*
			* Since the request structs are packed, memcpying from type_id's address with size equal to the struct's size
			* should copy the request data accurately.
			*/
			memcpy(outbuf, &_SAY->type_id, MSGSIZE);
			pthread_mutex_lock(&lock2);
			clients = this_channel->users;
			i=0;
			while(clients[i]){
				printf("sending message to (%s)", clients[i]->hostaddrp);
				//FIX: tmp_sockfd
				n = sendto(tmp_sockfd, outbuf, MSGSIZE, 0, (struct sockaddr *)&clients[i]->clientaddr, sizeof(clientaddr));
				if(n < 0)
					debug("failed to send message to client");
				i++;
			}
			pthread_mutex_unlock(&lock2);
			free(_SAY);
			req_Q->waiting[j] = NULL;
		}

		req_Q->size = 0;	
	}
}

void queue_say_request(struct _REQ_NEW * req, int idx){
	struct _REQ_SAY * _SAY;
	char *uname;
	int index = idx;
	int i,n;

	_SAY = malloc(sizeof(struct _REQ_SAY));
 	if(!_SAY){
		debug("handle_request failed to allocate space for Say request");
		return;
	}

	memset(_SAY, 0, sizeof(struct _REQ_SAY));
	_SAY->type_id = _IN_SAY;
	memcpy(_SAY->channel_name, this_channel->name, NAMELEN);
	memcpy(_SAY->user_name, this_channel->users[index]->uname, NAMELEN);
	memcpy(_SAY->text_field, &req->data[sizeof(uint32_t)+NAMELEN], TEXTLEN);

	pthread_mutex_lock(&lock1);
	if(req_Q_backlog->size < 128){	
		req_Q_backlog->waiting[req_Q_backlog->size] = _SAY;
		req_Q_backlog->size++;
	}
	pthread_mutex_unlock(&lock1);
	
	printf(logging_msg, 128, "[*] SERVER-LOG: Queued Say request:\n\ttype_id: %d\n\tchannel name: %s\n\tuser name: %s\n\tmessage: %s",
		_SAY->type_id, _SAY->channel_name, _SAY->user_name, _SAY->text_field);
	//server_log(logging_msg);

	return;
}

struct channel * channel_lookup(char * ch_name){
	int i;

	for(i=0; i < ch_mgr->size; i++){
		if((strncmp(ch_name, ch_mgr->channels[i]->name, NAMELEN)) == 0)
			return(ch_mgr->channels[i]);
	}
	return NULL;
}

uint32_t handle_request(struct _REQ_NEW * req){
	/**/
	char msg[MSGSIZE+4]; //4 extra bytes are used for null-byte padding and 64bit alignment
	uint32_t type_id = 0;
	struct AUTHD_CLIENT *client;
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

	if(type_id != _IN_LOGIN){
		client = client_lookup(req->hostaddrp, NULL);
		if(client == NULL){
			server_log("Received request from non-authenticated user");
			return _IN_ERROR;
		}
	}

	if(type_id == _IN_LOGIN){
		server_log("Type: Login");
		server_log("Client requested to login to channel");
		if(req->size != (sizeof(uint32_t)+NAMELEN)){
			server_log("Login request has invalid size");
			return(_IN_ERROR + _IN_LOGIN);
		}

		memcpy(msg, &req->data[4], NAMELEN);
		client = client_lookup(req->hostaddrp, msg);
		if(client == NULL){
			server_log("Logging in client");
                	client = client_login(req, msg);
			if(client == NULL){
				debug("Login request failed in client_login");
				return(_IN_ERROR + _IN_LOGIN);
			}else{
				printf("[*] Client (%s) auth struct:\tthis: %p\tnext: %p\tprev: %p\n", client->user_s->uname, client, client->next, client->prev);
				printf("[*] Client user struct:\thostaddrp: %s\tname: %s\tchannel_list: %p\n", client->user_s->hostaddrp, client->user_s->uname, client->user_s->ch_list);
			}
			//handle_join_request(tmp_sockfd, ch_mgr->channels[0], client->user_s, ch_mgr->channels[0]->name);
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
		if(req->size != sizeof(uint32_t)){
			server_log("Logout request has invalid size");
			return(_IN_ERROR + _IN_LOGOUT);
		}
		struct AUTHD_CLIENT *client;
		client = client_lookup(req->hostaddrp, NULL);
		if(client){
			client_logout(client);
		}else{
			server_log("Received logout request from non-authenticated user");
			return(_IN_ERROR + _IN_LOGOUT);
		}

		return _IN_LOGOUT;	

	}else if(type_id == _IN_JOIN){
                server_log("Type: Join");
		if(req->size != (sizeof(uint32_t)+NAMELEN)){
			server_log("Join request has invalid size");
			return(_IN_ERROR + _IN_JOIN);
		}
		//FIX: hardcoded sizeof(uint32_t) and [4] sizes. replace with #define TYPELEN
		memcpy(msg, &req->data[4], NAMELEN);
		if(handle_join_request(tmp_sockfd, channel_lookup(msg), client->user_s, msg))
			return(_IN_ERROR + _IN_JOIN);

		return _IN_JOIN;

	}else if(type_id == _IN_LEAVE){
                server_log("Type: Leave");	
		if(req->size != (sizeof(uint32_t)+NAMELEN)){
			server_log("Leave request has invalid size");
			return(_IN_ERROR + _IN_JOIN);
		}
		memcpy(msg, &req->data[4], NAMELEN);
		if((handle_leave_request(channel_lookup(msg), client->user_s)) == -1){
			server_log("Handle leave request failed");
			return(_IN_ERROR + _IN_LEAVE);
		}

		return _IN_LEAVE;

	}else if(type_id == _IN_SAY){
		server_log("Master Received Type: Say");
		/*Resolve channel and forward the Say message.*/
		memcpy(msg, &req->data[4], NAMELEN);
		struct channel *ch = channel_lookup(msg);
		if(ch != NULL){
			memset(&shmem_user, 0, sizeof(struct SHMEM_USR_ACTION));
			shmem_user.type_id = _IN_SAY;
			memcpy(&shmem_user.user_name, msg, NAMELEN);
			memcpy(&shmem_user.text_field, &req->data[NAMELEN+4], TEXTLEN);
			memcpy(&shmem_user.clientaddr, &req->clientaddr, sizeof(struct sockaddr_in));
			puts("Say request enqueued for child");
			shmem_enqueue(ch);
			/*
			if(ch->sockfd > 0 && &ch->serveraddr != NULL){
				n = sendto(ch->sockfd, req->data, MSGSIZE, 0, (struct sockaddr *)&ch->serveraddr, sizeof(struct sockaddr_in));
				if(n < 0){
					server_log("Failed to forward Say message to channel.");
				}else{
					server_log("Successfully forwarded Say message to channel.");
				}
			}
			*/
		}else{
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

void destroy_channel(){
	int i;

	/*Lock mutexes to ensure threads finish current task before exiting*/
	pthread_mutex_lock(&lock1);
	pthread_mutex_lock(&lock2);

	server_log("Cleaning up after children");

	sem_unlink(this_channel->name);
        sem_close(this_channel->sem_lock);
        if(this_channel->shmem)
                munmap(this_channel->shmem, sizeof(struct SHMEM_USR_ACTION)+8);
        i=0;
        while(this_channel->users[i]){
                if(this_channel->users[i]->hostaddrp)
                        free(this_channel->users[i]->hostaddrp);

                free(this_channel->users[i]);
                i++;
        }
        if(i != this_channel->num_users)
                debug("found mismatch between free'd user structs and num_users");

        free(this_channel->users);
        close(tmp_sockfd);

	exit(0);
}

void *shmem_dequeue(void *argvp){
	unsigned int offset=0;
	unsigned int size=0;
	int i, n;
	struct channel *ch = this_channel;
	struct _REQ_NEW msg;
	char req_buf[(SHMEM_USER_SIZE*SHMEM_STCK_SIZE)+8];
	
	while(1){
		sem_wait(ch->sem_lock);
		memcpy(&size, ch->shmem, sizeof(size));
		if(size > 0){
			server_log("Copying shmem");
			memset(req_buf, 0, (SHMEM_USER_SIZE*SHMEM_STCK_SIZE)+8);
			memcpy(req_buf, (ch->shmem)+sizeof(size), (SHMEM_USER_SIZE*size));
			memset(ch->shmem, 0, (SHMEM_USER_SIZE*SHMEM_STCK_SIZE)+sizeof(size));
		}
		sem_post(ch->sem_lock);

		offset=0;
		for(i=0; i<size; i++){
			memset(&shmem_user, 0, SHMEM_USER_SIZE);
			memcpy(&shmem_user, req_buf+offset, SHMEM_USER_SIZE);
			snprintf(logging_msg, 128, "shmem_user: type_id: %u\t name: %s\t msg: %s\t@ offset: %u\n",shmem_user.type_id, shmem_user.user_name, shmem_user.text_field, offset);
			server_log(logging_msg);
			if(shmem_user.type_id == _IN_SAY){
				memset(&msg, 0, sizeof(struct _REQ_NEW));
				msg.size = MSGSIZE;
				msg.hostaddrp = resolve_client(&shmem_user.clientaddr);
				printf("resolve_client returned: %s\n", msg.hostaddrp);
				memcpy(msg.data, &shmem_user, MSGSIZE);
				memcpy(&msg.clientaddr, &shmem_user.clientaddr, sizeof(struct sockaddr_in));
				n = user_lookup(msg.hostaddrp, NULL);
				printf("==== n returned: %d\t enqueueing msg.data: %s\n", n, &msg.data[4+NAMELEN]);
				if(n > -1)
					queue_say_request(&msg, n);

			}else if(shmem_user.type_id == _IN_JOIN){
				join_channel(&shmem_user);
			}else if(shmem_user.type_id == _IN_LEAVE){
				if((leave_channel(&shmem_user)) == 1){
					printf("shmem_dequeue thread is returning\n");
					return NULL;
				}
			}
			//Handle request
			offset+=SHMEM_USER_SIZE;
		}
	}
}

void *thread_accept(void *argvp){
	struct _REQ_NEW *msg;
	uint32_t msg_type;
	int sockfd, n;

	memcpy(&sockfd, argvp, sizeof(int));

	while(1){
		msg = accept_input_blk(sockfd);
		memcpy(&msg_type, msg->data, sizeof(uint32_t));

		if(msg_type == _IN_SAY){
			server_log("Type: Say");
			if(msg->size != MSGSIZE){
				server_log("Say request has invalid size");
				continue;
			}
			if(strncmp(&msg->data[sizeof(uint32_t)], this_channel->name, strlen(this_channel->name))){
				server_log("Say request sent to wrong channel");
				continue;
			}else{
				n = user_lookup(msg->hostaddrp, NULL);
				if(n < 0){
					server_log("received Say request from non-authenticated user");
					continue;
				}
			queue_say_request(msg, n);
			}
		}
		free(msg);
	}

}

void start_channel(int sfd, struct channel *ch){
	//struct _REQ_NEW * msg;
	char *userhost_addr;
	//uint32_t msg_type;
	int sockfd = sfd;
	int *sock;
	int i, n;

	tmp_sockfd = sockfd;
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

	sock = &sockfd;

	pthread_create(&tid[0], NULL, send_requests, NULL);
	pthread_create(&tid[1], NULL, shmem_dequeue, NULL);
	pthread_create(&tid[2], NULL, thread_accept, sock);

	pthread_join(tid[1], NULL);
	destroy_channel();
	while(1){
		/*
		if(msg_type == _IN_ERROR || msg_type == (msg_type + _IN_ERROR)){
			debug("Server received invalid request");
			free(msg);
			continue;
		}

		if(msg_type == _IN_LOGOUT){
			debug("Closing channel and exiting child process");
			free(msg);
			destroy_channel();
		}

		free(msg);
		*/
	}

}

void *create_shmem(size_t size){
	int prot = PROT_READ | PROT_WRITE;
	int vis = MAP_ANONYMOUS | MAP_SHARED;
	void *mem;

	mem = mmap(NULL, size, prot, vis, 0, 0);
	if(mem)
		memset(mem, 0, size);

	return mem;
}

int init_channel_sem(struct channel *ch){
	ch->sem_value = 1;

	if(!(ch->sem_lock = sem_open(ch->name, O_CREAT | O_EXCL, 0644, ch->sem_value))){
		perror("ERROR: ");
		sem_unlink(ch->name);
		sem_close(ch->sem_lock);
		return 1;
	}

	server_log("Semaphore initialized");
	return 0;
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

	if(!strlen(name))
		error("ERROR: channel name cannot be null");

	memset(ch->name, 0, NAMELEN);
	strncpy(ch->name, name, NAMELEN);

	sockfd = bind_new_socket(serveraddr, portno);
	ch->sockfd = sockfd;
	serverlen = sizeof(serveraddr);

	/*Resolve OS-assigned port number*/
	if(getsockname(sockfd, (struct sockaddr *)&serveraddr, &serverlen))
		error("ERROR: getsockname failed");
	portno = ntohs(serveraddr.sin_port);
	ch->portno = portno;
	memcpy(&ch->serveraddr, &serveraddr, serverlen);
	snprintf(ch->portstr, MAXUINTLEN, "%d", portno);

	ch->shmem = create_shmem((SHMEM_USER_SIZE * SHMEM_STCK_SIZE)+4);
	if(!ch->shmem)
		error("ERROR: shmem is NULL");

	if(init_channel_sem(ch))
		if(init_channel_sem(ch))
			error("ERROR: init_channel_sem");

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

void shmem_enqueue(struct channel *ch){
	unsigned int offset=0;
	unsigned int size=0;
	int i;

	sem_wait(ch->sem_lock);
	memcpy(&size, ch->shmem, sizeof(size));

	if(size >= SHMEM_STCK_SIZE){
		server_log("shmem stack is full. Signal child to clean it up");
	}else{
		offset = (size * SHMEM_USER_SIZE) + sizeof(size);
		size++;
		memcpy((ch->shmem)+sizeof(size), &shmem_user, SHMEM_USER_SIZE);
		memcpy(ch->shmem, &size, sizeof(size));
		offset=4;
	}

	sem_post(ch->sem_lock);

	return;
}

int handle_leave_request(struct channel *ch, struct user *client){
	if(ch == NULL){
		server_log("handle_leave_request received NULL channel *");
		return -1;
	}
	if(client == NULL){
		server_log("handle_leave_request received NULL client *");
		return -1;
	}

	remove_channel_user(client, ch);
	/*
	memset(&shmem_user, 0, sizeof(struct SHMEM_USR_ACTION));
	shmem_user.type_id = _IN_LEAVE;
	memcpy(shmem_user.user_name, client->uname, NAMELEN);
	memcpy(&shmem_user.clientaddr, &clientaddr, clientlen);

	shmem_enqueue(ch);
	*/
	server_log("leave request sent to child.");

	return 0;
}

int handle_join_request(int sfd, struct channel* ch, struct user *client, char *channel_name){
	struct hostent *hostp;
	char * hostaddrp;
	int n, sockfd;

	sockfd = sfd;

	hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        if (hostp == NULL)
                error("ERROR on gethostbyaddr");

        hostaddrp = inet_ntoa(clientaddr.sin_addr);
        if (hostaddrp == NULL)
                error("ERROR on inet_ntoa\n");

	if(ch == NULL){
		if(channel_name == NULL){
			debug("handle_join_request received NULL channel_name");
			return -1;
		}
		n = strlen(channel_name);
		if(n < 1 || n > NAMELEN){
			debug("handle_join_request received invalid channel_name length");
			return -1;
		}
		ch_mgr->channels[ch_mgr->size] = create_channel(channel_name, 0);
		ch = ch_mgr->channels[ch_mgr->size];
		ch_mgr->size++;
	}

	n = add_channel_user(client, ch);
	printf("[*] add_channel_user returned: %d\n", n);
	int i = 0;
	struct channel_list *ch_list;
	ch_list = client->ch_list;
	printf("[*] User Channel List:\n");
	while(ch_list){
		printf("Channel# %d\tName: %s\tNext: %p\tPrev: %p\n", i, ch_list->ch->name, ch_list->ch_next, ch_list->ch_prev);
		ch_list = ch_list->ch_next;
		i++;
	}
	if(n != 0)
		return -1;

	memset(&shmem_user, 0, sizeof(struct SHMEM_USR_ACTION));
        shmem_user.type_id = _IN_JOIN;
        memcpy(shmem_user.user_name, client->uname, NAMELEN);
        memcpy(&shmem_user.clientaddr, &clientaddr, clientlen);

	shmem_enqueue(ch);

	server_log("Join request sent to child");
	snprintf(logging_msg, 128, "received join request from %s (%s)\n", hostp->h_name, hostaddrp);
	server_log(logging_msg);
        //printf("[*] SERVER-LOG:  \treceived login request from %s (%s)\n", hostp->h_name, hostaddrp);

       //n = sendto(sockfd, ch->portstr, strlen(ch->portstr), 0, (struct sockaddr *)&clientaddr, clientlen);
       // if (n < 0)
        //        error("ERROR in sendto");

	return 0;
}

int main(int argc, char** argv) {
	struct _REQ_NEW *msg;
	uint32_t msg_type;
	int sockfd, portno, debug_portno, optval, n, req_size;
	struct sockaddr_in serveraddr;
	//struct channel_MGR *ch_mgr;

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
	* Init outgoing request queue and backlog
	*/
	req_Q = malloc(sizeof(struct _REQ_QUEUE));
	req_Q_backlog = malloc(sizeof(struct _REQ_QUEUE));
	if(!req_Q || !req_Q_backlog)
		error("ERROR: failed to allocate space for request queues");

	memset(req_Q, 0, sizeof(struct _REQ_QUEUE));
	memset(req_Q_backlog, 0, sizeof(struct _REQ_QUEUE));
	req_Q->size = 0;
	req_Q_backlog->size = 0;
	SHMEM_USER_SIZE = sizeof(struct SHMEM_USR_ACTION);
	SHMEM_SAY_SIZE = sizeof(struct SHMEM_SAY_ACTION);
        SHMEM_STCK_SIZE = 16;
	thread_exit = 0;

	/*
	*Initialize Channel Manager struct and create Commons channel
	*/
	ch_mgr = (struct channel_MGR*)malloc(sizeof(struct channel_MGR*));
	ch_mgr->size = 0;
	ch_mgr->channels = malloc(1024 * (sizeof(struct channel*)));
	ch_mgr->channels[0] = create_channel("Commons", debug_portno);
	ch_mgr->size++;

	req_size = sizeof(struct _REQ_LOGIN);
        struct _REQ_LOGIN * _LOGIN = malloc(req_size);
	tmp_sockfd = sockfd;
	//if(!(client_list = malloc(sizeof(struct AUTHD_CLIENT))))
	//	error("ERROR: malloc failed to allocate space for client_list");
	//memset(client_list, 0, sizeof(struct AUTHD_CLIENT));
	
	while(1){
		msg = accept_input_blk(sockfd);
		msg_type = handle_request(msg);

		//if(msg_type == _IN_LOGIN){
		//	memcpy(_LOGIN, msg->data, req_size);
		//	new_connection(sockfd, ch_mgr->channels[0], _LOGIN->user_name);
		//}//else if(msg_type == _IN_JOIN){
		/*	ch_mgr->channels = malloc(1024 * (sizeof(struct channel*)));
       			ch_mgr->channels[1] = create_channel("OtherChannel", 0);
        		ch_mgr->size++;
			
		}*/
		free(msg);
	}

	//while(ch_mgr->channels[i]){
		
	//}

	return 0;
}





