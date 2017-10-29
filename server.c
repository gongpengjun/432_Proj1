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
	sem_t *sem_lock;
	unsigned int sem_value;
	void *shmem;
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

pthread_t tid;
pthread_mutex_t lock1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock2 = PTHREAD_MUTEX_INITIALIZER;
struct _REQ_QUEUE * req_Q;
struct _REQ_QUEUE * req_Q_backlog;
struct channel *this_channel;
struct channel **channel_arr;
struct sockaddr_in **connected_clients;
struct sockaddr_in clientaddr;
char *hostaddrp;
int clientlen;
int tmp_sockfd;

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

	/*Resolve ip addr of client and check if ip exists in connected users*/
	msg->hostaddrp = resolve_client(&msg->clientaddr);
	snprintf(logging_msg, 128, "resolved client address: %s", msg->hostaddrp);
	server_log(logging_msg);

	return msg;
}

int client_logout(int index){
	int i = index;
	int n;
	struct user *client;

	client = this_channel->users[i];
	if(client){
		n = sendto(tmp_sockfd, &_IN_LOGOUT, sizeof(uint32_t), 0, (struct sockaddr *)&client->clientaddr, sizeof(clientaddr));
		if(n < 1)
			puts("Logout ack failed to send");
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
	
	snprintf(logging_msg, 128, "Queued Say request:\n\ttype_id: %d\n\tchannel name: %s\n\tuser name: %s\n\tmessage: %s",
		_SAY->type_id, _SAY->channel_name, _SAY->user_name, _SAY->text_field);
	server_log(logging_msg);

	return;
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
		if(req->size != (sizeof(uint32_t)+NAMELEN)){
			server_log("Login request has invalid size");
			return(_IN_ERROR + _IN_LOGIN);
		}

		memcpy(msg, &req->data[4], NAMELEN);
		if(user_lookup(req->hostaddrp, msg) < 0){
			pthread_mutex_lock(&lock2);
                	client_login(req, msg);
			pthread_mutex_unlock(&lock2);
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

		n = user_lookup(req->hostaddrp, NULL);
		if(n != -1){
			pthread_mutex_lock(&lock2);
			client_logout(n);
			pthread_mutex_unlock(&lock2);
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
		return _IN_JOIN;
		//break;

	}else if(type_id == _IN_LEAVE){
                server_log("Type: Leave");
		server_log("client requested to kill channel connection");
		return _IN_LEAVE;

	}else if(type_id == _IN_SAY){
		server_log("Type: Say");
		if(req->size != MSGSIZE){
			server_log("Say request has invalid size");
			return(_IN_ERROR + _IN_SAY);
		}

		if(strncmp(&req->data[sizeof(uint32_t)], this_channel->name, strlen(this_channel->name))){
			server_log("Say request sent to wrong channel");
			return(_IN_ERROR + _IN_SAY);
		}

		n = user_lookup(req->hostaddrp, NULL);
		if(n < 0){
			server_log("received Say request from non-authenticated user");
			return(_IN_ERROR + _IN_SAY);
		}

		queue_say_request(req, n);	
		
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

void test_shmem(){
	unsigned int i;
	char str1[]="Child accessed shmem\n";

	puts("[*] Testing Shmem");
	i = sem_getvalue(this_channel->sem_lock, &this_channel->sem_value);
	printf("sem_lock value: %u\n", i);

	sem_wait(this_channel->sem_lock);
	printf("Child read: %s\n", this_channel->shmem);
	strncpy(this_channel->shmem, str1, strlen(str1));
	sem_post(this_channel->sem_lock);

	puts("Child unlocked semaphore");
	return;
}

void start_channel(int sfd, struct channel *ch){
	struct _REQ_NEW * msg;
	char *userhost_addr;
	uint32_t msg_type;
	int sockfd = sfd;
	int i, n;

	tmp_sockfd = sockfd;

	this_channel = ch;
	test_shmem();
	sem_unlink(this_channel->name);
        sem_close(this_channel->sem_lock);

	//this_channel = ch;
	this_channel->num_users = 0;
	this_channel->users = malloc(MAXCLIENTNUM * sizeof(struct user*));
	if(!this_channel->users)
		error("ERROR: start_channel() failed to malloc space for users");

	for(i=0; i<MAXCLIENTNUM; i++){
		this_channel->users[i] = NULL;	
	}
	
	if(sockfd < 0)
		error("ERROR: start_channel() received bad sockfd");

	pthread_create(&tid, NULL, send_requests, NULL);

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
		}

		free(msg);	
	}

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

	close(sockfd);
	exit(0);
}

void *create_shmem(size_t size){
	int prot = PROT_READ | PROT_WRITE;
	int vis = MAP_ANONYMOUS | MAP_SHARED;

	return mmap(NULL, size, prot, vis, 0, 0);
}

int init_channel_sem(struct channel *ch){
	sem_t *sem_lock;	

	//sem_lock = &ch->sem_lock;
	ch->sem_value = 1;

	if(!(ch->sem_lock = sem_open(ch->name, O_CREAT | O_EXCL, 0644, ch->sem_value))){
		perror("ERROR: ");
		sem_unlink(ch->name);
		sem_close(ch->sem_lock);
		return 1;
	}
	//memcpy(&ch->sem_lock, &sem_lock, sizeof(sem_t));
	puts("Semaphore initialized");
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
	snprintf(ch->portstr, MAXUINTLEN, "%d", portno);

	ch->shmem = create_shmem(sizeof(struct user)+8);
	if(!ch->shmem)
		error("ERROR: shmem is NULL");
	memset(ch->shmem, 0, (sizeof(struct user)+8));

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

	/*
	*Initialize Channel Manager struct and create Commons channel
	*/
	ch_mgr = (struct channel_MGR*)malloc(sizeof(struct channel_MGR*));
	ch_mgr->size = 0;
	ch_mgr->channels = malloc(1024 * (sizeof(struct channel*)));
	ch_mgr->channels[0] = create_channel("Commons", debug_portno);
	ch_mgr->size++;

	struct channel *ch = ch_mgr->channels[0];
	sem_wait(ch->sem_lock);
	printf("Parent read: %s\n", ch->shmem);
	strncpy(ch->shmem, "Parent was here\n", 17);
	sem_post(ch->sem_lock);
	printf("Parent unlocked semaphore\n");

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





