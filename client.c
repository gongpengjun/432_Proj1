#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include "raw.h"

#define BUFSIZE 512
#define NAMELEN 32
#define TEXTLEN 64
#define REQSIZE 100 //sizeof(type_id) + sizeof(channel_name) + sizeof(text_field)

const uint32_t _OUT_LOGIN = 0;
const uint32_t _OUT_LOGOUT = 1;
const uint32_t _OUT_JOIN = 2;
const uint32_t _OUT_LEAVE = 3;
const uint32_t _OUT_SAY = 4;
const uint32_t _OUT_LIST = 5;
const uint32_t _OUT_WHO = 6;
const uint32_t _OUT_LIVE = 7;
const uint32_t _OUT_ERROR = 99;

const uint32_t _IN_SAY = 0;
const uint32_t _IN_LIST = 1;
const uint32_t _IN_WHO = 2;
const uint32_t _IN_ERROR = 3;

const char _CMD_EXIT[]="exit";
const char _CMD_JOIN[]="join";
const char _CMD_LEAVE[]="leave";
const char _CMD_LIST[]="list";
const char _CMD_WHO[]="who";
const char _CMD_SWITCH[]="switch";

void switch_channel(char *name);
struct channel *join_channel(char *name);
void send_master_request(uint32_t t);
void send_channel_request(uint32_t t);

struct __attribute__((__packed__)) _REQ_LOGIN{
	uint32_t type_id;
	char user_name[NAMELEN];
}_LOGIN;

struct __attribute__((__packed__)) _REQ_LOGOUT{
	uint32_t type_id;
}_LOGOUT;

struct __attribute__((__packed__)) _REQ_JOIN{
	uint32_t type_id;
	char channel_name[NAMELEN];
}_JOIN;

struct __attribute__((__packed__)) _REQ_LEAVE{
	uint32_t type_id;
	char channel_name[NAMELEN];
}_LEAVE;

struct __attribute__((__packed__)) _REQ_SAY{
	uint32_t type_id;
	char channel_name[NAMELEN];
	//char user_name[NAMELEN];
	char text_field[TEXTLEN];
}_SAY;

struct __attribute__((__packed__)) _REQ_LIST{
	uint32_t type_id;
}_LIST;

struct __attribute__((__packed__)) _REQ_WHO{
	uint32_t type_id;
	char channel_name[NAMELEN];
}_WHO;

struct __attribute__((__packed__)) _REQ_LIVE{
	uint32_t type_id;
}_LIVE;

void **_REQ_ARRAY[8];
unsigned int _REQ_SIZES[8];

struct session_info{
	char *name;
	//char active_channel[NAMELEN+4];
	struct _MASTER_INFO *_master;
	//struct hostent *server;
	struct channel *channels[1024];
	struct channel *_active_channel;
	int num_channels;
};

struct _MASTER_INFO{
	struct sockaddr_in serveraddr;
	struct hostent *server;
	int portno;
	int sockfd;
};

struct channel{
	char name[NAMELEN+4];
	struct sockaddr_in serveraddr;
	//int sockfd;
	int portno;
};

struct _PENDING_CHANNEL{
	struct channel *ch;
	struct _PENDING_CHANNEL *next;
	struct _PENDING_CHANNEL *prev;
};

char DEFAULT_HOST[] = "127.0.0.1";
int DEFAULT_PORT = 4444;

//int sockfd, portno, master_sockfd, master_portno;
int serverlen;
char *input_bp;
unsigned int input_size;
//struct sockaddr_in serveraddr;
//struct sockaddr_in master_serveraddr;
//struct hostent *server;
struct session_info *session;
struct _PENDING_CHANNEL *pending_channel_list;
//struct channel *pending_channels[128];
//char *hostname;

pthread_t tid;
pthread_mutex_t lock1 = PTHREAD_MUTEX_INITIALIZER;

void error(char *msg) {
	perror(msg);
	exit(0);
}

void resolve_host(char *hostname, int portno) {
	struct _MASTER_INFO *master;

	if(session->_master == NULL){
		session->_master = malloc(sizeof(struct _MASTER_INFO));
		if(!session->_master)
			error("ERROR: session master failed to init.");
		memset(session->_master, 0, sizeof(struct _MASTER_INFO));
	}else{
		printf("[*] DEBUG: session master channel was not NULL\n");
	}

	master = session->_master;

    	/* create the socket */
	master->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (master->sockfd < 0) 
		error("ERROR opening socket");

  	/* get the server's DNS entry */
	master->server = gethostbyname(hostname);
	if (master->server == NULL) {
		fprintf(stderr,"ERROR, no such host as %s\n", hostname);
		exit(0);
	}

	master->serveraddr.sin_family = AF_INET;
	bcopy((char *)master->server->h_addr, (char *)&master->serveraddr.sin_addr.s_addr, master->server->h_length);
	master->serveraddr.sin_port = htons(portno);
	master->portno = portno;
	
	return;
}

uint32_t build_request(uint32_t t, int argc, char **argv){
	uint32_t type = t;
	size_t n;

	if(type == _OUT_LOGIN){
		if(session->name){
			memset(&_LOGIN, 0, sizeof(struct _REQ_LOGIN));
			_LOGIN.type_id = type;
			memcpy(_LOGIN.user_name, session->name, NAMELEN);
			//printf("Login request:\nType: %d\nName: %s\n", _LOGIN.type_id, _LOGIN.user_name);
			return _LOGIN.type_id;
		}
	}else if(type == _OUT_LOGOUT){
		_LOGOUT.type_id = type;
		return _LOGOUT.type_id;

	}else if(type == _OUT_JOIN){
		//argv[0] is the command name: 'join'
		if(argc == 2){
			memset(&_JOIN, 0, sizeof(struct _REQ_JOIN));
			_JOIN.type_id = type;
			n = strlen(argv[1]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_JOIN.channel_name, argv[1], NAMELEN);
			//printf("Join request:\nType: %d\nChannel: %s\n\n", _JOIN.type_id, _JOIN.channel_name);
			return _JOIN.type_id;
		}
	}else if(type == _OUT_LEAVE){
		//command
		if(argc == 2){
			memset(&_LEAVE, 0, sizeof(struct _REQ_LEAVE));
			_LEAVE.type_id = type;
			n = strlen(argv[1]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_LEAVE.channel_name, argv[1], NAMELEN);
			//printf("Leave request:\nType: %d\nChannel: %s\n\n", _LEAVE.type_id, _LEAVE.channel_name);
			return _LEAVE.type_id;
		}else{
			printf("Command Error: /leave was given an invalid number of arguments\n");
		}
	}else if(type == _OUT_SAY){
		if(argc == 2){
			memset(&_SAY, 0, sizeof(struct _REQ_SAY));
			_SAY.type_id = type;
			n = strlen(argv[0]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_SAY.channel_name, argv[0], NAMELEN);
			n = strlen(argv[1]);
			if(n > TEXTLEN)
				return _IN_ERROR;
			memcpy(_SAY.text_field, argv[1], TEXTLEN);
			//printf("Say request:\nType: %d\nChannel: %s\nText: %s\n", _SAY.type_id, _SAY.channel_name, _SAY.text_field);
			return _SAY.type_id;
		}
	}else if(type == _OUT_LIST){
		memset(&_LIST, 0, sizeof(struct _REQ_LIST));
		_LIST.type_id = type;
		return _LIST.type_id;

	}else if(type == _OUT_WHO){
		//command
		if(argc == 2){
			memset(&_WHO, 0, sizeof(struct _REQ_WHO));
			_WHO.type_id = type;
			n = strlen(argv[1]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_WHO.channel_name, argv[1], NAMELEN);
			//printf("Who request:\nType: %d\nChannel: %s\n\n", _WHO.type_id, _WHO.channel_name);
			return _WHO.type_id;
		}
	}else if(type == _OUT_LIVE){
		_LIVE.type_id = type;
		return _LIVE.type_id;
	}else{
		puts("ERROR: build_request() received bad request type");
		return _IN_ERROR;
	}

	return _IN_ERROR;
}

void resolve_cmd(char * input){
	char cmd[BUFSIZE+1];
	char **argv;
	int i, offset, n;
	int argc = 0;

	memset(cmd, 0, BUFSIZE+1);

	n=0;
	for(i=1; i<BUFSIZE; i++){
		//uses i-1 to dispense of '/' char
		if(input[i] < 0x21 || input[i] > 0x7e){ 
			cmd[i-1] = 0x0;
		}else{
			n++;
			cmd[i-1] = input[i];
		}
	}

	i=0;
	n=0;
	while(i<BUFSIZE+1){
		n = strlen(&cmd[i]);
		if(n < 1){
			i++;
			continue;
		}
		i+=n+1;
		argc++;
		//If the 1st string (i.e. 'switch') is longer than 7, we assume an invalid command
		if(argc < 2 && n > 7){
			printf("Invalid command\n");
			return;
		}
	}
	//printf("DEBUG: argc = %d\n", argc);

	argv = malloc(sizeof(char *) * argc);
	if(!argv)
		error("ERROR: in resolve_cmd() failed to allocate argv");

	offset = 0;
	for(i=0; i<argc; i++){	
		n = strlen(&cmd[offset]);
		if(n < 1)
			error("ERROR: received command arg with invalid size");

		argv[i] = malloc(n+1);
		if(!argv[i])
			error("ERROR: in resolve_cmd() failed to allocate argc");

		memset(argv[i], 0, n+1);
		strcpy(argv[i], &cmd[offset]);
		offset+=n+1;
		if(offset > BUFSIZE+1)
			error("ERROR: offset ran out of buffer bounds");	
	}

	if(memcmp(argv[0], _CMD_EXIT, strlen(_CMD_EXIT)) == 0){
		if(build_request(_OUT_LOGOUT, 0, NULL) != _OUT_LOGOUT){
			puts("ERROR: build_request failed");
			//free argv's and argv
			return;
		}
		send_master_request(_OUT_LOGOUT);
		exit(0);

	}else if(memcmp(argv[0], _CMD_JOIN, strlen(_CMD_JOIN)) == 0){
		if(build_request(_OUT_JOIN, argc, argv) != _OUT_JOIN){
			puts("ERROR: build_request failed");
			return;
		}else if(!(join_channel(_JOIN.channel_name))){
			return;
		}
		send_master_request(_OUT_JOIN);

	}else if(memcmp(argv[0], _CMD_LEAVE, strlen(_CMD_LEAVE)) == 0){
		if(build_request(_OUT_LEAVE, argc, argv) != _OUT_LEAVE){
			puts("ERROR: build_request failed");
			return;
		}
		send_master_request(_OUT_LEAVE);

	}else if(memcmp(argv[0], _CMD_LIST, strlen(_CMD_LIST)) == 0){
		if(build_request(_OUT_LIST, 0, NULL) != _OUT_LIST){
			puts("ERROR: build_request failed");
			return;
		}
		send_master_request(_OUT_LIST);

	}else if(memcmp(argv[0], _CMD_WHO, strlen(_CMD_WHO)) == 0){
		if(build_request(_OUT_WHO, argc, argv) != _OUT_WHO){
			puts("ERROR: build_request failed");
			return;
		}
		send_master_request(_OUT_WHO);

	}else if(memcmp(argv[0], _CMD_SWITCH, strlen(_CMD_SWITCH)) == 0){
		/*No request needed, client keeps track of this*/
		switch_channel(argv[1]);

	}else{
		printf("Command '%s' not recognized.\n", argv[0]);
	}


	for(i=0; i<argc; i++){
		free(argv[i]);
	}
	free(argv);

	return;
}

struct channel *search_channels(char *name){
	int i;
	struct channel *ch;

	for(i=0; i < session->num_channels; i++){
		ch = session->channels[i];
		if(!strncmp(ch->name, name, NAMELEN))
			return ch;
	}
	return NULL;
}

void switch_channel(char *name){
	struct channel *ch;

	ch = search_channels(name);
	if(!ch){
		printf("[*] DEBUG: channel %s not found.\n", name);
		return;
	}

	session->_active_channel = ch;
	if(ch->portno > 0){
		session->_active_channel->serveraddr.sin_port = htons(ch->portno);
	}else{
		printf("[*] DEBUG: switch_channel has invalid port number from requested channel\n");
	}

	return;
}

struct _PENDING_CHANNEL *new_pending_channel(){
	struct _PENDING_CHANNEL *pend_ch;

	if(!pending_channel_list){
		pending_channel_list = malloc(sizeof(struct _PENDING_CHANNEL));
		if(!pending_channel_list){
			printf("ERROR: in new_pending_channel, malloc failed to allocate pending_channel_list.\n");
			return NULL;
		}
		memset(pending_channel_list, 0, sizeof(struct _PENDING_CHANNEL));
		pend_ch = pending_channel_list;
		return pend_ch;
	}

	pend_ch = pending_channel_list;
	while(pend_ch->next)
		pend_ch = pend_ch->next;

	pend_ch->next = malloc(sizeof(struct _PENDING_CHANNEL));
	if(!pend_ch->next){
		printf("ERROR: in new_pending_channel, malloc failed to allocate pend_ch->next.\n");
		return NULL;
	}
	memset(pend_ch->next, 0, sizeof(struct _PENDING_CHANNEL));
	pend_ch->next->prev = pend_ch;
	pend_ch = pend_ch->next;
	
	return pend_ch;
}

struct channel *search_pending_channels(char *name){
	struct channel *ch;
	struct _PENDING_CHANNEL *pend_ch;

	if(!pending_channel_list)
		return NULL;

	if(!pending_channel_list->ch){
		free(pending_channel_list);
		pending_channel_list = NULL;
		return NULL;
	}

	if((strncmp(name, pending_channel_list->ch->name, NAMELEN)) == 0){
		ch = pending_channel_list->ch;
		if(pending_channel_list->next){
			pend_ch = pending_channel_list->next;
			pend_ch->prev = NULL;
			free(pending_channel_list);
			pending_channel_list = pend_ch;
		}else{
			free(pending_channel_list);
			pending_channel_list = NULL;
		}
		return ch;
	}

	pend_ch = pending_channel_list;
	while(pend_ch->next){
		pend_ch = pend_ch->next;
		if(!pend_ch->ch){
			printf("[*] DEBUG: in pending channel search, found pending channel struct in list without valid channel\n");
		}
		if((strncmp(name, pend_ch->ch->name, NAMELEN)) == 0){
			ch = pend_ch->ch;
			if((pend_ch->next != NULL) && (pend_ch->prev != NULL)){
				pend_ch->next->prev = pend_ch->prev;
				pend_ch->prev->next = pend_ch->next;
			}else if(pend_ch->next != NULL){
				pend_ch->next->prev = NULL;
			}else if(pend_ch->prev != NULL){
				pend_ch->prev->next = NULL;
			}
			free(pend_ch);
			return ch;
		}
	}

	return NULL;

}

struct channel *join_channel(char *name){
	struct channel *new_ch;
	struct _PENDING_CHANNEL *pend_ch;
	int n;

	n = strlen(name);
	if(n < 1 || n > NAMELEN){
		printf("[*] DEBUG: join_channel received invalid channel name\n");
		return NULL;
	}
	if(search_channels(name)){
		printf("[*] CLIENT-LOG: already subscribed to channel %s\n", name);
		return NULL;
	}

	pend_ch = new_pending_channel();
	new_ch = malloc(sizeof(struct channel));
	if(!pend_ch || !new_ch){
		printf("ERROR: failed to allocate new channel\n");
		return NULL;
	}

	memset(new_ch, 0, sizeof(struct channel));
	memcpy(new_ch->name, name, NAMELEN);

	/*Init new channel to serveraddr and portno of master*/
	memcpy(&new_ch->serveraddr, &session->_master->serveraddr, sizeof(struct sockaddr_in));
	new_ch->portno = session->_master->portno;

	session->channels[session->num_channels] = new_ch;
	session->num_channels++;
	session->_active_channel = new_ch;
	//printf("[*] DEBUG: Joining channel: %s\n", new_ch->name);
	//Add channel to pending channels
	pend_ch->ch = new_ch;

	return new_ch;
}

void send_master_request(uint32_t t){
	char out_buf[REQSIZE];
	uint32_t type_id;
	int n, size, portno;
	struct _MASTER_INFO *master;

	if(t > 7 || t < 0){
		printf("[*] DEBUG: send_master_request received bad type\n");
		return;
	}
	type_id = t;
	size = _REQ_SIZES[type_id];
	if(_REQ_ARRAY[type_id] == NULL || size < 0 || size > REQSIZE){
		printf("[*] DEBUG: send_master_request received invalid request size\n");
		return;
	}
	memset(out_buf, 0, REQSIZE);
	memcpy(out_buf, _REQ_ARRAY[type_id], size);
	master = session->_master;
	/*Set portno to master portno*/

	n = sendto(master->sockfd, out_buf, size, 0, (struct sockaddr *)&master->serveraddr, sizeof(struct sockaddr_in));
	if(n < 0)
		printf("[*] DEBUG: send_master_request failed to send request\n");

	return;
}

void send_channel_request(uint32_t t){
	char out_buf[REQSIZE];
	char buf[BUFSIZE];
	uint32_t type_id;
	struct channel *active_ch;
	int n, size, ch_portno;

	if(t > 7 || t < 0){
		printf("[*] DEBUG: send_channel_request received bad type\n");
                return;
	}

	type_id = t;
	size = _REQ_SIZES[type_id];
	if(_REQ_ARRAY[type_id] == NULL || size < 0 || size > REQSIZE){
		printf("[*] DEBUG: send_channel_request received invalid request size\n");
		return;
	}

	memset(out_buf, 0, REQSIZE);

	if(session->_active_channel){
		active_ch = session->_active_channel;
		if(active_ch->portno < 1){
			printf("[*] DEBUG: send_channel_request got invalid port number from active channel\n");
			return;
		}
	}
	//printf("[*] DEBUG: Active Channel Info:\n\tName: %s\n\tS_Addr: %u\n\tPort: %d\n\n", active_ch->name, active_ch->serveraddr.sin_addr.s_addr, active_ch->portno);

	memcpy(out_buf, _REQ_ARRAY[type_id], size);

	n = sendto(session->_master->sockfd, out_buf, size, 0, (struct sockaddr *)&active_ch->serveraddr, sizeof(struct sockaddr_in));
	if(n < 0)
		error("ERROR: sendto failed");
	
	return;
}

void *recv_request(void *vargp){
	char input[BUFSIZE];
	char name[NAMELEN+4];
	struct sockaddr_in serveraddr;
	struct channel *ch;
	int n, serverlen, sockfd, i;
	int offset = 8;

	serverlen = sizeof(serveraddr);
	memset(&serveraddr, 0, serverlen);
	memset(name, 0, NAMELEN+4);
	//mutex lock
	if(session->_master){
		if(session->_master->sockfd > 0){
			sockfd = session->_master->sockfd;
		}else{
			printf("[*] DEBUG: recv_request received invalid sockfd from session->_master\n");
			exit(1);
		}
	}else{
		printf("[*] DEBUG: recv_request received NULL session->_master\n");
		exit(1);
	}

	while(1){
		memset(input, 0, BUFSIZE);	
		n = recvfrom(sockfd, input, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
		if (n < 0){
			puts("recvfrom failed in recv_request");
		}else if(!memcmp(input, &_IN_SAY, 4)){	
			for(i=0; i <= input_size; i++){
				write(1, "\b", 1);
			}
			printf("[%s][%s]: %s\n", &input[4], &input[36], &input[68]);
			//printf("Received message: \n\t\ttype_id:\t0x%08x \n\t\tchannel:\t%s \n\t\tuser:\t\t%s \n\t\tmessage:\t%s\n", input, &input[4], &input[36], &input[68]);
			//printf("Message came from port: %d\n", ntohs(serveraddr.sin_port));	
			if(pending_channel_list){
				//printf("[*] DEBUG: checking pending_channel_list\n");
				if(session->_active_channel->portno == session->_master->portno){	
					memcpy(name, &input[4], NAMELEN);
					//printf("[*] CLIENT-LOG: recv_request received Say request from non-active channel: %s\n", name);
					//printf("Serveraddr Info:\n\tin_addr: %u\n\tportno: %d\n\n", serveraddr.sin_addr.s_addr, serveraddr.sin_port);
					//Search pending join channels
					ch = search_pending_channels(name);
					if(ch){
						ch->serveraddr.sin_port = serveraddr.sin_port;
						ch->portno = ntohs(serveraddr.sin_port);
					}	
				}
			}
			write(1, "> ", 2);
			for(i=0; i<input_size; i++){
				write(1, &input_bp[i], 1);
			}
		}else if(!memcmp(input, &_IN_WHO, 4)){
			uint32_t num_users;
			memcpy(&num_users, &input[4], 4);
			if(num_users > 0 && (num_users*32) < n){	
				printf("Users on channel %s:\n", &input[offset]);
				for(i=0; i<num_users; i++){
					offset+=32;
					printf("%s\n", &input[offset]);
					if(offset > BUFSIZE)
						;
				}
			}else{
				printf("ERROR (2): Who response had invalid number of users field (%u)\n", num_users);
			}
			
		}else if(!memcmp(input, &_IN_LIST, 4)){
			uint32_t num_chs;
			memcpy(&num_chs, &input[4], 4);
			if(num_chs > 0 && (num_chs*32) < n){
				offset = 8;
				printf("Existing channels:\n");
				for(i=0; i<num_chs; i++){
					printf("%s\n", &input[offset]);
					offset+=32;
					if(offset > BUFSIZE)
						i+=num_chs;
				}	
			}else{
				printf("ERROR (1): List response had invalid number of channels field (%u)\n", num_chs);
			}
		}else if(!memcmp(input, &_IN_ERROR, 4)){
			printf("Server Error:\n %s\n", &input[4]);
		}
		//if(!memcmp(input, &_OUT_LOGOUT, 4)){	
		//	break;
		//}
	}
	pthread_exit(NULL);

}

void user_prompt(){
	//char *input;
	char *input2;
	char **argv;
	int n;

	input_bp = (char *)malloc(BUFSIZE);
	if(!input_bp)
		error("ERROR: malloc returned null in user_prompt()");
	input2 = (char *)malloc(BUFSIZE);
	if(!input2)
		error("ERROR: malloc");
	memset(input2, 0, BUFSIZE);
	argv = malloc((sizeof(char *))*2);
	if(!argv)
		error("ERROR: malloc returned null in user_prompt()");
	//argv[0] = session->_active_channel->name;
	argv[1] = input_bp;

	//raw_mode();
	while(1){
		input_size = 0;
		memset(input_bp, 0, BUFSIZE);
		write(1, "> ", 2);

		n=0;
		argv[0] = session->_active_channel->name;
		while(n < BUFSIZE){	
			if((read(0, &input_bp[n], 1)) < 1)
				break;
			if(input_bp[n] == 0x0a || input_bp[n] == 0x00){
				//input[n] = 0x00;
				break;
			}	
			n++;
			input_size++;	
		}
		memcpy(input2, input_bp, BUFSIZE);

		if(input2[0] == 0x2f){
			resolve_cmd(input2);
		}else{	
			build_request(_OUT_SAY, 2, argv);
			send_channel_request(_OUT_SAY);
		}
	}

	free(argv);
	free(input2);

	return;
}

int init_server_connection(char *hostname, int portno) {
	int n, serverlen;
	char buf[BUFSIZE];
	char out_buf[BUFSIZE];
	struct _MASTER_INFO *master;
	char *argv[2] = {"join", "Common"};

	memset(buf, 0, BUFSIZE);
	memset(out_buf, 0, BUFSIZE);

	resolve_host(hostname, portno);
	if(session->_master){
		master = session->_master;
	}else{
		error("ERROR: init_server_connection received NULL session->_master.");
	}

	session->channels[session->num_channels] = malloc(sizeof(struct channel));
	memset(session->channels[session->num_channels], 0, sizeof(struct channel));

	/* Start server handshake */
	serverlen = sizeof(struct sockaddr_in);
	build_request(_OUT_LOGIN, 0, NULL);
	send_master_request(_OUT_LOGIN);

	if(build_request(_OUT_JOIN, 2, argv) != _OUT_JOIN){
                        puts("ERROR: build_request failed");
                        return -1;
        }
	if(!(join_channel(_JOIN.channel_name))){
			puts("ERROR: join channel failed while initializing server connections");
                        return -1;
        }
        send_master_request(_OUT_JOIN);

	return 0;
}

int main(int argc, char **argv) {
	char *hostname;
	int portno;

    	/* check command line arguments */
	if (argc != 4) {
		puts("Usage: ./client <hostname> <port> <username>");
		exit(1);
	}

	session = malloc(sizeof(struct session_info));
	if(!session)
		error("ERROR: main() failed to allocate session struct");
	memset(session, 0, sizeof(struct session_info));

	hostname = argv[1];
	if(!hostname){
		puts("ERROR: received invalid hostname");
		exit(1);
	}

	portno = atoi(argv[2]);
	if(!portno){
		puts("ERROR: received invalid port number");
		exit(1);
	}

	session->name = malloc(NAMELEN+4);
	if(!session->name)
		error("ERROR: main() failed to allocate space for user's name");
	
	strncpy(session->name, argv[3], NAMELEN);
	pending_channel_list = NULL;
	/*Fix this. Channel should not default to Commons until login succeeds*/
	//char channel[]="Commons";
	//strncpy(session->active_channel, channel, NAMELEN);

	_REQ_ARRAY[0] = (void *)&_LOGIN;
	_REQ_SIZES[0] = sizeof(struct _REQ_LOGIN);

	_REQ_ARRAY[1] = (void *)&_LOGOUT;
	_REQ_SIZES[1] = sizeof(struct _REQ_LOGOUT);

	_REQ_ARRAY[2] = (void *)&_JOIN;
	_REQ_SIZES[2] = sizeof(struct _REQ_JOIN);

	_REQ_ARRAY[3] = (void *)&_LEAVE;
	_REQ_SIZES[3] = sizeof(struct _REQ_LEAVE);

	_REQ_ARRAY[4] = (void *)&_SAY;
	_REQ_SIZES[4] = sizeof(struct _REQ_SAY);

	_REQ_ARRAY[5] = (void *)&_LIST;
	_REQ_SIZES[5] = sizeof(struct _REQ_LIST);

	_REQ_ARRAY[6] = (void *)&_WHO;
	_REQ_SIZES[6] = sizeof(struct _REQ_WHO);

	_REQ_ARRAY[7] = (void *)&_LIVE;
	_REQ_SIZES[7] = sizeof(struct _REQ_LIVE);
		
	if((init_server_connection(hostname, portno)) == 0){
		pthread_create(&tid, NULL, recv_request, NULL);
		user_prompt();
	}

	free(session->name);
	free(session);
	exit(0);
}








