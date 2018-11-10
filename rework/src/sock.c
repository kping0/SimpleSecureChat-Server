#include "sock.h"

int ip_listen_port(int port)
{
	/* init vars */
	int sock = 0;
	struct sockaddr_in addr;
	
	/* fill struct with req info */
	addr.sin_family = AF_INET;		
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	sock = socket(AF_INET, SOCK_STREAM, 0); /* create socket */
	if(sock < 0)
	{
		logerr("failed to create socket");
		exit(EXIT_FAILURE);
	}
	
	int enable = 1;
	
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) != 0) /* set REUSEADDR to on */
	{
		logerr("setsocketopt() failed on socket");
		exit(EXIT_FAILURE);	
	}

	if( bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) /* bind socket */
	{
		logerr("unable to bind socket, maybe socket is in use ? (server already running)");
		exit(EXIT_FAILURE);	
	}
	
	/* start listening on socket */
	if( listen(sock, 1) < 0 )
	{
		logerr("cannot listen on socket");
		exit(EXIT_FAILURE);
	}

	assert(sock != 0); /* failsafe */
	return sock;	
}
