
/*
 *  <SimpleSecureChat Client/Server - E2E encrypted messaging application written in C>
 *  Copyright (C) 2017-2018 The SimpleSecureChat Authors. <kping0> 
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h> 
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 
#include <my_global.h>
#include <mysql.h>

#include "sscsrvfunc.h" //most functions code
#include "settings.h" //compile time settings definitions
#include "protected_malloc.h" //heap allocation code
#include "base64.h" // base64 code
#include "serialization.h" //Serialization code
#include "hashing.h" // hashing user authkey code (SHA256)
#include "cstdinfo.h" //custom error & info printing
#include "simpleconfig.h" //configfile support
#include "loadconfig.h" //config loading code
#include "handler.h" // client handler code

int sock = 0; /* listening socket */

SCONFIG* config = NULL; /* Global SimpleConfig configuration */

SSL_CTX *ctx = NULL; /* Global SSL Context */

int main(void){
     debuginfo();
     config = loadconfig();	

if(sconfig_get_int(config,"SSCS_LOGTOFILE") == 1){
	byte* logfilepath = sconfig_get_str(config,"SSCS_LOGFILE");
	FILE* stdoutl = freopen(logfilepath,"a+",stdout);
        FILE* stderrl = freopen(logfilepath,"a+",stderr); 
        cinitfd(stdoutl,stderrl);
}
    //register signal handlers..
    signal(SIGINT,ssc_sig_handler);
    signal(SIGABRT,ssc_sig_handler);
    signal(SIGTERM,ssc_sig_handler);
    signal(SIGCHLD,childexit_handler);
    //Init MYSQL Database
    init_DB();
	
    //initalize openssl and create the ssl_ctx context
    init_openssl();
    ctx = create_context();

    configure_context(ctx);
    sock = create_socket(5050); //Setup listening socket
   /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
	
        int client = accept(sock, (struct sockaddr*)&addr, &len); //Accept Client Connections.
#ifdef SSCS_LOG_IP_ADDRESSES
	cinfo("Inbound Connection from %s:%i",inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
#endif /* SSCS_LOG_IP_ADDRESSES */

		struct sscs_handler_data* hdl_data = cmalloc(sizeof(struct sscs_handler_data));
		/* check removed (cmalloc checks itself) */
		hdl_data->client_socket = client;
		hdl_data->ctx = ctx;
		
	#ifdef SSCS_CLIENT_FORK

	/*
	 * We fork(clone the process) to handle each client.
	 */

		pid_t pid = fork();
		if(pid == 0){ //If the pid is 0 we are running in the child process(our designated handler) 		
			ClientHandler(hdl_data);
		}
		cfree(hdl_data);

	#else
	
	/*
	 * We spawn a thread that calls the ClientHandler to handle each client.
	 */

		pthread_t thr_id;
		if(pthread_create(&thr_id,NULL,ClientHandler,hdl_data)){
			cerror(" failed to create thread  %s\n",strerror(errno));
			cfree(hdl_data);
			exit(0);
		}

	#endif
    } 
    cdebug(" Server Main Process is shutting down..\n");
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    sconfig_close(config);
    return 0;
}

