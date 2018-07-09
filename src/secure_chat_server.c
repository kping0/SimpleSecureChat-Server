
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

#include "sscsrvfunc.h" //Some SSL functions 
#include "settings.h" //settings for ssc
#include "protected_malloc.h"
#include "base64.h" //MIT base64 function (BSD LICENSE)
#include "serialization.h" //SSCS Library
#include "hashing.h" // hashing implimentation (SHA256(salt+data))
#include "cstdinfo.h" //custom error & info printing
#include "simpleconfig.h" //configfile support
#include "loadconfig.h"

struct sscs_handler_data{
	int client_socket;
	SSL_CTX* ctx;
	pthread_t* thread_info;	
};

/*
 * Global Variables. Tried to avoid as much as possible but for the listening socket it is neccessary so the signal handler can close it & the configuration pointer needs to be accessed by so many functions
 * that it makes sense to make it a global
 */
int sock = 0; 

SCONFIG* config = NULL; /* Global SimpleConfig configuration */

SSL_CTX *ctx = NULL; /* Global SSL Context */

void* _ClientHandler(void* data);

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
	cinfo("Connection from: %s:%i",inet_ntoa(addr.sin_addr),(int)ntohs(addr.sin_port));

		struct sscs_handler_data* _hdl_data = cmalloc(sizeof(struct sscs_handler_data));
		if(!_hdl_data){
			cerror(" Failed to allocate memory for thread_data\n");
			exit(0);
		}

		_hdl_data->client_socket = client;
		_hdl_data->ctx = ctx;
		
	#ifdef SSCS_CLIENT_FORK

	/*
	* We fork(clone the process) to handle each client. On exit these zombies are handled
	* by childexit_handler
	*/
		pid_t pid = fork();
		if(pid == 0){ //If the pid is 0 we are running in the child process(our designated handler) 		
			_ClientHandler(_hdl_data);
		}
		cfree(_hdl_data);
	#else
		pthread_t _thr_id;
		if(pthread_create(&_thr_id,NULL,_ClientHandler,_hdl_data)){
			cerror(" failed to create thread  %s\n",strerror(errno));
			cfree(_hdl_data);
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
void* _ClientHandler(void* data){
		debuginfo();
		struct sscs_handler_data* client_info = data;
		int client = client_info->client_socket;
		SSL_CTX* ctx = client_info->ctx;

		signal(SIGINT,SIG_DFL); //unbind sigint for segfault
		cmalloc_init();	
		if (client < 0) {
		    perror("Unable to accept");
		    exit(EXIT_FAILURE);
		}
		//Setup ssl with the client.
	 	SSL *ssl = NULL;
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		BIO *accept_bio = BIO_new_socket(client, BIO_CLOSE);
		SSL_set_bio(ssl, accept_bio, accept_bio);
		SSL_accept(ssl);
		ERR_print_errors_fp(stderr);
		BIO *bio = BIO_pop(accept_bio);
		assert(ssl != NULL);
		char* buf = cmalloc(4096); //Main receive buffer for receiving from SSL socket
		MYSQL* db = get_handle_DB();
		while(1){ //Handle request until interrupt or connection problems	
			memset(buf,'\0',4096);
			int r = SSL_read(ssl,buf, 4095); 
			buf[4095] = '\0';
		    	switch (SSL_get_error(ssl, r)){ 
			    	case SSL_ERROR_NONE: 
			       		 break;
		    		case SSL_ERROR_ZERO_RETURN: 
		       		 	goto end; 
		    		default: 
		        		goto end;
		    	}
			sscso* obj0 = SSCS_open((byte*)buf);
			int msgp0  = SSCS_object_int(obj0,"msgp");
			cdebug(" Message arrived with message purpose %i\n",msgp0);
			if(msgp0 == REGRSA){ //User wants to register a username with a public key
				char* rusername = (char*)SSCS_object_string(obj0,"rusername");
				if(!rusername){
					cerror(" User wants to register but username not found in serialized object\n");
					goto end;
				}
				char* newline = strchr(rusername,'\n');
				if( newline ) *newline = 0;
	
				if(checkforUser(rusername,db) == 1){
					cdebug("Not adding user \"%s\"-> username already taken.\n",rusername);
					SSL_write(ssl,"ERR",3);
				}
				else{
					cdebug(" User \"%s\" is trying to register",rusername);
					char* b64rsa = (char*)SSCS_object_string(obj0,"b64rsa");
					int rsalen = SSCS_object_int(obj0,"rsalen");
					char* authkey = (char*)SSCS_object_string(obj0,"authkey");
					if(strlen(authkey) < 256) goto end;
					if(addUser2DB(rusername,b64rsa,rsalen,authkey,db) != 1){
						cerror(" inserting user %s\n",rusername);
						SSL_write(ssl,"ERR",3);
						goto end;
					}
					else{
						cdebug(" User \"%s\" registered\n",rusername);	
						SSL_write(ssl,"OK",2);
						cfree(rusername);
					}
				}
			}
			else if(msgp0 == AUTHUSR){ //User wants to authenticate so he can receive messages.
				cdebug(" User sent request to authenticate,handling...\n");
				char* userauthk = (char*)SSCS_object_string(obj0,"authkey");
				if(strlen(userauthk) < 256){
					cerror(" Authkey supplied <256 (%i)\n",(int)strlen(userauthk));
					goto end;
				}
				char* authusername = (char*)SSCS_object_string(obj0,"username");
				SSCS_HASH* hash = getUserAuthKeyHash(authusername,db);
				if(!hash){
					cerror(" Authkey returned by getUserAuthKey is NULL, exiting\n");
					goto end;
				}
				if(SSCS_comparehash((byte*)userauthk,strlen(userauthk),hash) == SSCS_HASH_VALID){
					cdebug(" User \"%s\" authenticated.\n",authusername);
					SSCS_release(&obj0);
					SSCS_freehash(&hash);
	/*
	 * Enter Second loop after authentication
	 */
					while(1){
						int r = SSL_read(ssl,buf, 4096); 
					    	switch (SSL_get_error(ssl, r))
					    	{ 
					    	case SSL_ERROR_NONE: 
					       		 break;
					    	case SSL_ERROR_ZERO_RETURN: 
							goto end; 
					    	default: 
							goto end;
					    	}
						buf[4095] = '\0';
						sscso* obj = SSCS_open((byte*)buf);
						int msgp = SSCS_object_int(obj,"msgp");
						/*
						* Important Functions are only accessible when user has authenticated.
						*/
						if(msgp == GETRSA){ //Client is requesting a User Public Key
							cdebug("Client Requested Public Key,handling...\n");
							char* rsausername = (char*)SSCS_object_string(obj,"username");
							const char* uRSAenc = GetEncodedRSA(rsausername,db);
							cdebug("Sending buffer \"%s\"\n",uRSAenc);
							if(uRSAenc){
								SSL_write(ssl,uRSAenc,strlen(uRSAenc));	
								cfree((void*)uRSAenc);
							}
							cfree(rsausername);
						}
						else if(msgp == MSGREC){ //Client is requesting stored messages
							char* retmsg = GetUserMessagesSRV(authusername,db);
							if(strlen(retmsg) != 0){ 
							#ifdef SSCS_OUTPUT_LIVE
								cdebug("User(%s) wants new messages, Sending Message with len %d -- %s",authusername,strlen(retmsg),retmsg);
							#endif
								SSL_write(ssl,retmsg,strlen(retmsg));
							}
							else{
								SSL_write(ssl,"ERROR",5);
							}
							//call function that returns an int,(messages available)send it to the client,and then send i messages to client in while() loop. 
						}
						else if(msgp == MSGSND){ //User wants to send a message to a user
							char* recipient = NULL;
							recipient = (char*)SSCS_object_string(obj,"recipient");
							if(!recipient){
								cerror(" Recipient for message not specified,exiting\n");
								goto end;
							}
							char* newline = strchr(recipient,'\n');
							if( newline ) *newline = 0;
							if(SSCS_object_string(obj,"sender") != NULL)goto end;
							SSCS_object_add_data(obj,"sender",(byte*)authusername,strlen(authusername));
							char* b64modbuf = obj->buf_ptr;
							cdebug("Buffering message from %s to %s\n",authusername,recipient);
							#ifdef SSCS_OUTPUT_LIVE
							cdebug("Message length %d -- content -- %s",strlen(obj->buf_ptr),obj->buf_ptr);
							#endif
							if(AddMSG2DB(db,recipient,(unsigned char*)b64modbuf) == -1){
								cerror(" Error occurred adding MSG to Database\n");
								SSL_write(ssl,"ERR",3);	
							}				
							else{
								SSL_write(ssl,"ACK",3);
							}
						}
						SSCS_release(&obj);
						fflush(stdout);
						fflush(stderr);
					}
				}
				else{
					cerror(" User %s failed to authenticate.\n",authusername);
					SSCS_freehash(&hash);
				}	
			}
			else{
				cerror(" ? Message received with no specific purpose, exiting...\n");
				SSCS_release(&obj0);
				goto end;
			}
			SSCS_release(&obj0);
			fflush(stdout);
			fflush(stderr);
		}
	end: //cleanup & exit
		cdebug(" Ending Client Session\n");
		BIO_free(bio);
		SSL_free(ssl);
		close(client); 
		mysql_close(db);
		cfree(buf); 
		cfree(data);

	#ifdef SSCS_CLIENT_FORK
		exit(0);
	#else
		pthread_exit(0);
	#endif
	/*
	* End of Client Handler Code
	*/

}
