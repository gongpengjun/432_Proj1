#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define BUFSIZE 512
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

const char _CMD_EXIT[]="exit";
const char _CMD_JOIN[]="join";
const char _CMD_LEAVE[]="leave";
const char _CMD_LIST[]="list";
const char _CMD_WHO[]="who";
const char _CMD_SWITCH[]="switch";

typedef struct _LOGIN_REQUEST{
	uint32_t type_id;
	char user_name[NAMELEN+4];
}_LOGIN_REQ;

typedef struct _SAY_REQUEST{
	uint32_t type_id;
	char channel_name[NAMELEN+4];
	char text_field[TEXTLEN+4];
}_SAY_REQ;

union _REQUEST{
	_LOGIN_REQ login;
	_SAY_REQ say;
};

struct session_info{
	char *name;
};

struct request_template{
	uint32_t type_id;
	char channel_name[NAMELEN];
	char user_name[NAMELEN];
	char text_field[TEXTLEN];
};

char DEFAULT_HOST[] = "127.0.0.1";
int DEFAULT_PORT = 4444;

int sockfd, portno;
struct sockaddr_in serveraddr;
struct hostent *server;
struct session_info *session;
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

int build_request(uint32_t t, int argc, char **argv){
	uint32_t type = t;
	size_t n;
	union _REQUEST request;

	if(type == _IN_LOGIN){
		if(session->name){
			memset(&request.login, 0, sizeof(struct _LOGIN_REQUEST));
			request.login.type_id = type;
			memcpy(request.login.user_name, session->name, NAMELEN);
			printf("Login request:\nType: %d\nName: %s\n", request.login.type_id, request.login.user_name);
			return 0;
		}
	}else if(type == _IN_LOGOUT){

	}else if(type == _IN_JOIN){

	}else if(type == _IN_LEAVE){

	}else if(type == _IN_SAY){
		if(argc == 2){
			memset(&request.say, 0, sizeof(struct _SAY_REQUEST));
			request.say.type_id = type;
			n = strlen(argv[0]);
			if(n > NAMELEN)
				return -1;
			memcpy(request.say.channel_name, argv[0], NAMELEN);
			n = strlen(argv[1]);
			if(n > TEXTLEN)
				return -1;
			memcpy(request.say.text_field, argv[1], TEXTLEN);
			printf("Say request:\nType: %d\nChannel: %s\nText: %s\n", request.say.type_id, request.say.channel_name, request.say.text_field);
		}

	}else if(type == _IN_LIST){

	}else if(type == _IN_WHO){

	}else if(type == _IN_LIVE){

	}else{
		puts("ERROR: build_noncmd_request() received bad request type");
		return -1;
	}

	return 0;
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

	//build_cmd_request(argc, argv);
	if(memcmp(argv[0], _CMD_EXIT, strlen(_CMD_EXIT)) == 0){
		build_request(_IN_LOGOUT, 0, NULL);

	}else if(memcmp(argv[0], _CMD_JOIN, strlen(_CMD_JOIN)) == 0){
		build_request(_IN_JOIN, argc, argv);

	}else if(memcmp(argv[0], _CMD_LEAVE, strlen(_CMD_LEAVE)) == 0){
		build_request(_IN_LEAVE, argc, argv);

	}else if(memcmp(argv[0], _CMD_LIST, strlen(_CMD_LIST)) == 0){
		build_request(_IN_LIST, 0, NULL);

	}else if(memcmp(argv[0], _CMD_WHO, strlen(_CMD_WHO)) == 0){
		build_request(_IN_WHO, argc, argv);

	}else if(memcmp(argv[0], _CMD_SWITCH, strlen(_CMD_SWITCH)) == 0){
		/*No request needed, client keeps track of this*/
		printf("Sure sure, switching to channel: %s\n", argv[1]);

	}else{
		printf("Command '%s' not recognized.\n", argv[0]);
	}


	for(i=0; i<argc; i++){
		free(argv[i]);
	}
	free(argv);

	return;
}

void send_request(char * out_buf){
	int n;

	int serverlen = sizeof(serveraddr);
	n = sendto(sockfd, out_buf, 4, 0, (struct sockaddr *)&serveraddr, serverlen);
	if(n < 0)
		error("ERROR: sendto failed");

	return;
}

void user_prompt(){
	char *input;
	int n;

	input = (char *)malloc(BUFSIZE);
	if(!input)
		error("ERROR: malloc returned null in user_prompt()");

	while(1){
		memset(input, 0, BUFSIZE);
		printf("> ");
		if(fgets(input, BUFSIZE, stdin) == NULL)
			continue;

		if(input[0] == 0x2f){
			resolve_cmd(input);
		}else if(input[0] == 0x2e){
			break;
		}else{
			printf("Sending message: %s\n", input);
		}
	}

	free(input);

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
	memset(session->name, 0, NAMELEN+4);
	strncpy(session->name, argv[3], NAMELEN);

	//init_server_connection();
	//user_prompt();
	build_request(_IN_LOGIN, 0, NULL);
	char ch_name[]="BigBossChannel";
	char text[]="Hello from big boss wtf..";
	char **testv = malloc((sizeof(char *))*2);
	testv[0] = ch_name;
	testv[1] = text;
	build_request(_IN_SAY, 2, testv);

	free(testv);
	free(session->name);
	free(session);
	return 0;
}








