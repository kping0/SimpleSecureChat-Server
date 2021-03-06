
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

#include "handler.h"

void* ClientHandler(void* data){ 
		debuginfo(); 
		struct sscs_handler_data* client_info = data; 
		int client = client_info->client_socket; 
		SSL_CTX* ctx = client_info->ctx; 
		signal(SIGINT,SIG_DFL); 
		cmalloc_init();	
		if(client < 0)cexit("client fd is below 0, exiting");
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
					cfree(rusername);
				}
				else{
					cdebug(" User \"%s\" is trying to register",rusername);
					char* b64rsa = (char*)SSCS_object_string(obj0,"b64rsa");
					int rsalen = SSCS_object_int(obj0,"rsalen");
					char* authkey = (char*)SSCS_object_string(obj0,"authkey");
					if(strlen(authkey) < 256){
						cfree(rusername);
						cfree(authkey);
						cfree(b64rsa);
						goto end;
					}
					if(addUser2DB(rusername,b64rsa,rsalen,authkey,db) != 1){
						cerror(" inserting user %s\n",rusername);
						SSL_write(ssl,"ERR",3);
						cfree(rusername);
						cfree(authkey);
						cfree(b64rsa);
						goto end;
					}
					else{
						cdebug(" User \"%s\" registered\n",rusername);	
						SSL_write(ssl,"OK",2);
						cfree(rusername);
						cfree(authkey);
						cfree(b64rsa);
					}
				}
			}
			else if(msgp0 == AUTHUSR){ //User wants to authenticate so he can receive messages.
				cdebug(" User sent request to authenticate,handling...\n");
				char* userauthk = (char*)SSCS_object_string(obj0,"authkey");
				if(strlen(userauthk) < 256){
					cerror(" Authkey supplied <256 (%i)\n",(int)strlen(userauthk));
					cfree(userauthk);
					goto end;
				}
				char* authusername = (char*)SSCS_object_string(obj0,"username");
				if(!authusername){
					cfree(userauthk);
					cerror("User did not supply a username to auth with.");
					goto end;
				}
				SSCS_HASH* hash = getUserAuthKeyHash(authusername,db);
				if(!hash){
					cerror(" Authkey returned by getUserAuthKey is NULL, exiting\n");
					cfree(userauthk);
					cfree(authusername);
					goto end;
				}
				if(SSCS_comparehash((byte*)userauthk,strlen(userauthk),hash) == SSCS_HASH_VALID){
					cdebug(" User \"%s\" authenticated.\n",authusername);
					SSCS_release(&obj0);
					SSCS_freehash(&hash);
					cfree(userauthk);
					/* move authusername to stack */
					int authusername_len = strlen(authusername);
					char authusername_stack[authusername_len+1];
					memcpy(authusername_stack,authusername,authusername_len);
					authusername_stack[authusername_len] = '\0';
					cfree(authusername);	
						
	/*
	 * Enter Second loop after authentication
	 */
					while(1){
						int r = SSL_read(ssl,buf, 4096); 
					    	switch (SSL_get_error(ssl, r)){ 
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
							if(!rsausername){
								cerror("no supplied username for GETRSA");
								goto end;
							}
							const char* uRSAenc = GetEncodedRSA(rsausername,db);
							if(uRSAenc){
								cdebug("Sending buffer \"%s\"\n",uRSAenc);
								SSL_write(ssl,uRSAenc,strlen(uRSAenc));	
								cfree((void*)uRSAenc);
							}
							else{
								SSL_write(ssl,"ERR",3);
							}
							cfree(rsausername);
						}
						else if(msgp == MSGREC){ //Client is requesting stored messages
							char* retmsg = GetUserMessagesSRV(authusername_stack,db);
							if(retmsg){
								if(strlen(retmsg) != 0){ 
								#ifdef SSCS_OUTPUT_LIVE
									cdebug("User(%s) wants new messages, Sending Message with len %d -- %s",authusername_stack,strlen(retmsg),retmsg);
								#endif
									SSL_write(ssl,retmsg,strlen(retmsg));
								}
								else{
									SSL_write(ssl,"ERROR",5);
								}
								cfree(retmsg);
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
								cerror("Recipient for message not specified,exiting\n");
								goto end;
							}
							char* newline = strchr(recipient,'\n');
							if( newline ) *newline = 0;
							char* sender_test_str = SSCS_object_string(obj,"sender");
							if(sender_test_str){
								cfree(sender_test_str);
								cfree(recipient);
								goto end;
							}
							SSCS_object_add_data(obj,"sender",(byte*)authusername_stack,strlen(authusername_stack));
							cdebug("Buffering message from %s to %s\n",authusername_stack,recipient);
							#ifdef SSCS_OUTPUT_LIVE
							cdebug("Message length %d -- content -- %s",strlen(obj->buf_ptr),obj->buf_ptr);
							#endif
							if(AddMSG2DB(db,recipient,obj->buf_ptr) == -1){
								cerror(" Error occurred adding MSG to Database\n");
								SSL_write(ssl,"ERR",3);	
							}				
							else{
								SSL_write(ssl,"ACK",3);
							}
							cfree(recipient);
						}
						SSCS_release(&obj);
						fflush(stdout);
						fflush(stderr);
					}
				}
				else{
					cerror("User %s failed to authenticate.\n",authusername);
					SSCS_freehash(&hash);
					SSCS_release(&obj0);
					SSCS_freehash(&hash);
					cfree(userauthk);
					cfree(authusername);
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
		if(config)sconfig_close(config);
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
