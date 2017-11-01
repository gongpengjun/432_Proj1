#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>

#define BUFSIZE 512
#define NAMELEN 32
#define TEXTLEN 64
#define REQSIZE 100 //sizeof(type_id) + sizeof(channel_name) + sizeof(text_field)

const uint32_t _IN_LOGIN = 0;
const uint32_t _IN_LOGOUT = 1;
const uint32_t _IN_JOIN = 2;
const uint32_t _IN_LEAVE = 3;
const uint32_t _IN_SAY = 4;
const uint32_t _IN_LIST = 5;
const uint32_t _IN_WHO = 6;
const uint32_t _IN_LIVE = 7;
const uint32_t _IN_ERROR = 99;

const char _CMD_EXIT[]="exit";
const char _CMD_JOIN[]="join";
const char _CMD_LEAVE[]="leave";
const char _CMD_LIST[]="list";
const char _CMD_WHO[]="who";
const char _CMD_SWITCH[]="switch";

void switch_channel(char *name);
void send_request(uint32_t t);

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
	char active_channel[NAMELEN+4];
	struct channel *channels[1024];
	struct channel *_active_channel;
	int num_channels;
};

struct channel{
	char name[NAMELEN+4];
	int sockfd;
	int portno;
};

char DEFAULT_HOST[] = "127.0.0.1";
int DEFAULT_PORT = 4444;

int sockfd, portno, master_sockfd, master_portno;
struct sockaddr_in serveraddr;
struct sockaddr_in master_serveraddr;
struct hostent *server;
struct session_info *session;
char *hostname;

pthread_t tid;

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

uint32_t build_request(uint32_t t, int argc, char **argv){
	uint32_t type = t;
	size_t n;

	if(type == _IN_LOGIN){
		if(session->name){
			memset(&_LOGIN, 0, sizeof(struct _REQ_LOGIN));
			_LOGIN.type_id = type;
			memcpy(_LOGIN.user_name, session->name, NAMELEN);
			printf("Login request:\nType: %d\nName: %s\n", _LOGIN.type_id, _LOGIN.user_name);
			return _LOGIN.type_id;
		}
	}else if(type == _IN_LOGOUT){
		_LOGOUT.type_id = type;
		return _LOGOUT.type_id;

	}else if(type == _IN_JOIN){
		//argv[0] is the command name: 'join'
		if(argc == 2){
			memset(&_JOIN, 0, sizeof(struct _REQ_JOIN));
			_JOIN.type_id = type;
			n = strlen(argv[1]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_JOIN.channel_name, argv[1], NAMELEN);
			printf("Join request:\nType: %d\nChannel: %s\n\n", _JOIN.type_id, _JOIN.channel_name);
			return _JOIN.type_id;
		}
	}else if(type == _IN_LEAVE){
		//command
		if(argc == 2){
			memset(&_LEAVE, 0, sizeof(struct _REQ_LEAVE));
			_LEAVE.type_id = type;
			n = strlen(argv[1]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_LEAVE.channel_name, argv[1], NAMELEN);
			printf("Leave request:\nType: %d\nChannel: %s\n\n", _LEAVE.type_id, _LEAVE.channel_name);
			return _LEAVE.type_id;
		}else{
			printf("Command Error: /leave was given an invalid number of arguments\n");
		}
	}else if(type == _IN_SAY){
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
			printf("Say request:\nType: %d\nChannel: %s\nText: %s\n", _SAY.type_id, _SAY.channel_name, _SAY.text_field);
			return _SAY.type_id;
		}
	}else if(type == _IN_LIST){
		memset(&_LIST, 0, sizeof(struct _REQ_LIST));
		_LIST.type_id = type;
		return _LIST.type_id;

	}else if(type == _IN_WHO){
		//command
		if(argc == 2){
			memset(&_WHO, 0, sizeof(struct _REQ_WHO));
			_WHO.type_id = type;
			n = strlen(argv[1]);
			if(n > NAMELEN)
				return _IN_ERROR;
			memcpy(_WHO.channel_name, argv[1], NAMELEN);
			printf("Who request:\nType: %d\nChannel: %s\n\n", _WHO.type_id, _WHO.channel_name);
			return _WHO.type_id;
		}
	}else if(type == _IN_LIVE){
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
	printf("DEBUG: argc = %d\n", argc);

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
		if(build_request(_IN_LOGOUT, 0, NULL) != _IN_LOGOUT){
			puts("ERROR: build_request failed");
			//free argv's and argv
			return;
		}
		send_request(_IN_LOGOUT);

	}else if(memcmp(argv[0], _CMD_JOIN, strlen(_CMD_JOIN)) == 0){
		if(build_request(_IN_JOIN, argc, argv) != _IN_JOIN){
			puts("ERROR: build_request failed");
			return;
		}
		send_request(_IN_JOIN);

	}else if(memcmp(argv[0], _CMD_LEAVE, strlen(_CMD_LEAVE)) == 0){
		if(build_request(_IN_LEAVE, argc, argv) != _IN_LEAVE){
			puts("ERROR: build_request failed");
			return;
		}
		send_request(_IN_LEAVE);

	}else if(memcmp(argv[0], _CMD_LIST, strlen(_CMD_LIST)) == 0){
		if(build_request(_IN_LIST, 0, NULL) != _IN_LIST){
			puts("ERROR: build_request failed");
			return;
		}
		send_request(_IN_LIST);

	}else if(memcmp(argv[0], _CMD_WHO, strlen(_CMD_WHO)) == 0){
		if(build_request(_IN_WHO, argc, argv) != _IN_WHO){
			puts("ERROR: build_request failed");
			return;
		}
		send_request(_IN_WHO);

	}else if(memcmp(argv[0], _CMD_SWITCH, strlen(_CMD_SWITCH)) == 0){
		/*No request needed, client keeps track of this*/
		//printf("Sure sure, switching to channel: %s\n", argv[1]);
		switch_channel("chan1");

	}else{
		printf("Command '%s' not recognized.\n", argv[0]);
	}


	for(i=0; i<argc; i++){
		free(argv[i]);
	}
	free(argv);

	return;
}

void switch_channel(char *name){
	int i;
	struct channel *ch;

	for(i=0; i < session->num_channels; i++){
		ch = session->channels[i];
		if(!strncmp(ch->name, name, NAMELEN)){
			session->_active_channel = ch;
			serveraddr.sin_port = htons(ch->portno);
			return;
		}
	}

	printf("DEBUG: channel not found: %s\n", name);

	return;
}

void send_request(uint32_t t){
	char out_buf[REQSIZE];
	char buf[BUFSIZE];
	uint32_t type = t;
	int n, size, new_portno;

	if(type > 7)
		error("ERROR: send_request() got invalid request type");

	size = _REQ_SIZES[type];
	memset(out_buf, 0, REQSIZE);

	if(_REQ_ARRAY[type] == NULL || size < 0 || size > REQSIZE)
		error("ERROR: send_request() received invalid request size");

	memcpy(out_buf, _REQ_ARRAY[type], size);
	
	int serverlen = sizeof(serveraddr);

	if(type == _IN_LOGOUT || type == _IN_JOIN){
		serveraddr.sin_port = htons(master_portno);
		memset(buf, 0, BUFSIZE);
		n = sendto(sockfd, out_buf, size, 0, (struct sockaddr *)&serveraddr, serverlen);
		//add mutex lock
		/*puts("Waiting for join req ack");
		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
		printf("Server requested to use port# %s\n", buf);
        	new_portno = atoi(buf);

        	session->channels[session->num_channels] = malloc(sizeof(struct channel));
        	memset(session->channels[session->num_channels], 0, sizeof(struct channel));
        	strncpy(session->channels[session->num_channels]->name, _JOIN.channel_name, NAMELEN);
        	session->_active_channel = session->channels[session->num_channels];
        	session->num_channels++;
		serveraddr.sin_port = htons(new_portno);
		*/
		puts("Sent join request");
		return;
	}

	n = sendto(sockfd, out_buf, size, 0, (struct sockaddr *)&serveraddr, serverlen);
	if(n < 0)
		error("ERROR: sendto failed");

	if(type == _IN_LOGOUT || _IN_JOIN)
		serveraddr.sin_port = htons(portno);
	
	return;
}

void *recv_request(void *vargp){
	char input[BUFSIZE];	
	int n, serverlen;

	serverlen = sizeof(serveraddr);
	while(1){
		memset(input, 0, BUFSIZE);
		n = recvfrom(sockfd, input, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
		if (n < 0){
			puts("recvfrom failed in recv_request");
		}else if(!memcmp(input, &_IN_SAY, 4)){
			printf("Received message: \n\t\ttype_id:\t0x%08x \n\t\tchannel:\t%s \n\t\tuser:\t\t%s \n\t\tmessage:\t%s\n", input, &input[4], &input[36], &input[68]);
		}

		if(!memcmp(input, &_IN_LOGOUT, 4)){
			printf("Thread (%d) is returning\n", tid);
			break;
		}
	}
	pthread_exit(NULL);
	//return;
}

void user_prompt(){
	char *input;
	char **argv;
	int n;

	input = (char *)malloc(BUFSIZE);
	if(!input)
		error("ERROR: malloc returned null in user_prompt()");
	argv = malloc((sizeof(char *))*2);
	if(!argv)
		error("ERROR: malloc returned null in user_prompt()");
	argv[0] = session->active_channel;
	argv[1] = input;

	while(1){
		memset(input, 0, BUFSIZE);
		write(1, "> ", 2);

		n=0;
		while(n < BUFSIZE){
			if((read(0, &input[n], 1)) < 1)
				break;
			if(input[n] == 0x0a || input[n] == 0x00){
				input[n] = 0x00;
				break;
			}	
			n++;
		}

		if(input[0] == 0x2f){
			resolve_cmd(input);
		}else if(input[0] == 0x2e){
			break;
		}else{	
			build_request(_IN_SAY, 2, argv);
			send_request(_IN_SAY);
		}
	}

	free(argv);
	free(input);

	return;
}

int init_server_connection() {
	int n, serverlen;
	char buf[BUFSIZE];
	char out_buf[BUFSIZE];

	memset(buf, 0, BUFSIZE);
	memset(out_buf, 0, BUFSIZE);

	resolve_host();

	/* Start server handshake */
	serverlen = sizeof(serveraddr);     
	build_request(_IN_LOGIN, 0, NULL);
	send_request(_IN_LOGIN);
	n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&serveraddr, &serverlen);
	if (n < 0){
		puts("ERROR: login failed");
		return -1;
	}
	master_portno = portno;
	printf("Server requested to use port# %s\n", buf);
	portno = atoi(buf);
	serveraddr.sin_port = htons(portno);

	session->channels[session->num_channels] = malloc(sizeof(struct channel));
	memset(session->channels[session->num_channels], 0, sizeof(struct channel));
	strncpy(session->channels[session->num_channels]->name, "Commons", strlen("Commons"));
	session->_active_channel = session->channels[session->num_channels];
	session->num_channels++;

	//build_request(_IN_LOGIN, 0, NULL);
	//send_request(_IN_LOGIN);

	return 0;
}

int main(int argc, char **argv) {

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

	/*Fix this. Channel should not default to Commons until login succeeds*/
	char channel[]="Commons";
	strncpy(session->active_channel, channel, NAMELEN);

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
		
	if(init_server_connection() == 0){
		pthread_create(&tid, NULL, recv_request, NULL);
		user_prompt();
	}

	free(session->name);
	free(session);
	exit(0);
}








