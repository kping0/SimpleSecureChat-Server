
#include "session.h"

void ssc_handle_client(void* client_info_void)
{
	EXISTS(client_info_void);

	HANDLER_DATA* client_info = client_info_void; /* Cast client information to struct */

	/* retrieve ssl context */
	SSL_CTX* listen_context = client_info->ssl_ctx; 
	EXISTS(listen_context);

	int client_internal = client_info->client_conn; /* internal socket int */
	
	/* SSL socket with Client */
	SSL* ssl_client = SSL_new(listen_context);
	EXISTS(ssl_client);
	SSL* client_ssl = ssl_client; 

	SSL_set_fd(ssl_client,client_internal); /* bind SSL socket to listening socket */
	
	/* create accept bio and feed to ssl */
	BIO* accept_bio = BIO_new_socket(client_internal, BIO_CLOSE);
	SSL_set_bio(ssl_client, accept_bio, accept_bio);
	
	/* accept conn */
	SSLCHKFAIL(SSL_accept(ssl_client));
	EXISTS(ssl_client);	

	/* print errors */
	ERR_print_errors_fp(stderr);
	
	/* pop off accept bio */
	BIO* client_bio = BIO_pop(accept_bio);

	/* allocate 4096 byte reusable buffer */
	byte* usr_buf = custom_malloc(4096); 

	/* get MySQL handle */
	MYSQL* db_conn = get_db_handle();	
	EXISTS(db_conn);
	
	while(1)
	{
		memset(usr_buf,0x0,4096);
		int checkvalue = SSL_read(ssl_client,usr_buf,4095); /* read from socket */
		usr_buf[4095] = 0x0; /* sanity reasons add 0x0 */
		switch(SSL_get_error(ssl_client, checkvalue)) /* check for errors */
		{
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_ZERO_RETURN:
				goto END_CONN;
			default:
				goto END_CONN;
		}
		sscso* serialized_object = SSCS_open(usr_buf); /* open serialized buffer received */
		int message_purpose = SSCS_object_int(serialized_object,"msgp"); /* get message purpose */
		logdbg("Message arrived (purpose %i)",message_purpose);

		if(message_purpose == REGISTER_USER) /* new user wants to register */
		{
			logdbg("User sent registration request");
	
			byte* new_user_name = SSCS_object_string(serialized_object,"rusername"); /* retrieve username to register */
			if(new_user_name == NULL)
			{
				logerr("User wants to register but did not supply username");	
				goto END_CONN;
			}

			string_remove_newline(new_user_name); /* remove \n if exists */
			
			if(check_user_exists(new_user_name,db_conn) != 0) 
			{
				/* user already exists or error*/
				logdbg("Not adding user \" %s \" - username is already taken.",new_user_name);	
				SSL_write(client_ssl,"ERR",3); /* notify client */
				custom_free(new_user_name);
			}
			else
			{
				logdbg("Registering user \"%s\".",new_user_name);	

				byte* new_user_base64_rsa = SSCS_object_string(serialized_object,"b64rsa"); /* retrieve public key */
				if(new_user_base64_rsa == NULL) /* no supplied public key */
				{
					logerr("User wants to register but did not supply a public key");
					/* cleanup */
					custom_free(new_user_name);
					SSCS_release(&serialized_object);

					SSL_write(client_ssl,"ERR",3); /* notify client */
					goto END_CONN;
				}
				int new_user_rsa_len = SSCS_object_int(serialized_object,"rsalen"); /* retrieve rsa length */
				
				byte* new_user_auth_key = SSCS_object_string(serialized_object,"authkey"); /* retrieve to be set authkey */
				if(new_user_auth_key == NULL)
				{
					logerr("User wants to register but did not supply an auth key");			
					/* cleanup */
					custom_free(new_user_base64_rsa);
					custom_free(new_user_name);
					SSCS_release(&serialized_object);

					SSL_write(client_ssl,"ERR",3); /* notify client */
					goto END_CONN;
				}
				
				int new_user_auth_key_len = strlen(new_user_auth_key);
				if(new_user_auth_key_len < 256 || new_user_auth_key_len > 512) /* check if 256 < authkey < 512 */
				{
					logerr("User wants to register but auth key is either to small or too big (%d)",new_user_auth_key_len);	
					/* cleanup */
					custom_free(new_user_base64_rsa); 
					custom_free(new_user_name);
					custom_free(new_user_auth_key);
					SSCS_release(&serialized_object);

					SSL_write(client_ssl,"ERR",3); /* notify client */
					goto END_CONN;
					
				}
				if(add_user_to_db(new_user_name,new_user_base64_rsa,new_user_rsa_len,new_user_auth_key,db_conn) != 0) /* add user to database */
				{
					/* cleanup */
					custom_free(new_user_base64_rsa);
					custom_free(new_user_name);
					custom_free(new_user_auth_key);
					SSCS_release(&serialized_object);
					
					SSL_write(client_ssl,"ERR",3); /* notify client */
					goto END_CONN;
				}
				else
				{
					/* user has successfully registered */
					logdbg("User \"%s\" has successfully registered.",new_user_name);

					/* cleanup */
					custom_free(new_user_base64_rsa);
					custom_free(new_user_name);
					custom_free(new_user_auth_key);

					SSL_write(client_ssl,"OK",2);
					
				}
				
			}

			
		} /* REGISTER_USER */
		else if(message_purpose == AUTHENTICATE_USER) /* user wants to authenticate himself */
		{
			logdbg("User send authentication request");	

			byte* user_auth_key = SSCS_object_string(serialized_object,"authkey"); /* fetch auth key */
			if(user_auth_key == NULL)
			{
				logerr("User wants to authenticate but no authkey is supplied");			

				SSCS_release(&serialized_object);

				goto END_CONN;
			}
			
			int user_auth_key_len = strlen(user_auth_key); /* get auth key length */
			if(user_auth_key_len < 256 || user_auth_key_len > 512)
			{
				logerr("User wants to authenticate but authkey is either too long or too short ");	

				custom_free(user_auth_key);
				SSCS_release(&serialized_object);

				goto END_CONN;
			}
			
			byte* user_auth_name = SSCS_object_string(serialized_object,"username"); /* fetch auth name */
			if(user_auth_name == NULL)
			{
				logerr("User wants to authenticate but no auth name is supplied");

				custom_free(user_auth_key);
				SSCS_release(&serialized_object);
				
				goto END_CONN;
			}

			SSCS_HASH* user_verified_hash = get_user_auth_hash(user_auth_name,db_conn); /* retrieve stored hash for user */
			if(user_verified_hash == NULL)
			{
				logerr("No hash stored for user, fatal");
				
				/* cleanup */
				custom_free(user_auth_key);
				custom_free(user_auth_name);
				SSCS_release(&serialized_object);	

				goto END_CONN;
			}

			if(SSCS_comparehash(user_auth_key,user_auth_key_len,user_verified_hash) == SSCS_HASH_VALID)
			{
				/* user has authenticated */
				logdbg(" User \"%s\" successfully authenticated. ");
				
				/* move username to stack and free heap object */
				int user_auth_name_stack_len = strlen(user_auth_name);
				byte* user_auth_name_stack[user_auth_name_stack_len+1]; 
				memcpy(user_auth_name_stack,user_auth_name,user_auth_name_stack_len);
				user_auth_name_stack[user_auth_name_stack_len] = 0x0;	
					
				custom_free(user_auth_key);
				custom_free(user_auth_name);
				SSCS_release(&serialized_object);
				SSCS_freehash(&user_verified_hash);	
				
				while(1) /* secondary loop after authentication */
				{
					int checkvalue = SSL_read(client_ssl,usr_buf,4095); /* read from socket */
					switch(SSL_get_error(client_ssl,checkvalue)) /* check for errors */
					{
						case SSL_ERROR_NONE:
							break;
						case SSL_ERROR_ZERO_RETURN:
							goto END_CONN;
						default:
							goto END_CONN;
					}
					usr_buf[4095] = 0x0; /* sanity add null term  */
					sscso* serialized_object = SSCS_open(usr_buf); /* open serialized buffer */
					if(serialized_object == NULL) /* could not open buffer */
					{
						goto END_CONN;	
					}

					int message_purpose = SSCS_object_int(serialized_object,"msgp"); /* get message purpose */
					 
					/* figure out what to do with the rest of the message */


					if(message_purpose == REQUEST_USER_PUBLIC) /* user is asking for another users public key */
					{
						logdbg("request for public key received.");	
						byte* other_user_name = SSCS_object_string(serialized_object,"username"); /* get name of other user */
						if(other_user_name == NULL)
						{
							/* user did not specify the username (used to associate the public keys) */
							logerr("request for public key received but no username specified.");
							SSCS_release(&serialized_object);	
							SSL_write(client_ssl,"ERR",3); /* notify client */
							goto END_CONN;		
						}	
						
						byte* other_user_public_buf = get_encoded_public(other_user_name,db_conn);	/* get public key from MySQL db */
						if(other_user_public_buf != NULL)
						{
							SSL_write(client_ssl,other_user_public_buf,strlen(other_user_public_buf)); /* send buffer to client */
							custom_free(other_user_public_buf);
						}else
						{
							SSL_write(client_ssl,"ERR",3);	
						}
						custom_free(other_user_name);
					} /* REQUEST_USER_PUBLIC */
					else if(message_purpose == REQUEST_MESSAGES)
					{
						byte* message_buf = get_enc_user_messages(user_auth_name_stack,db_conn); /* retrieve messages (if any available) from database */
						if(message_buf != NULL)
						{
							/* message buffer is NOT NULL */
							int message_buf_len = strlen(message_buf); /* get length of message buffer */
							if(message_buf_len != 0)
							{
								SSL_write(client_ssl,message_buf,strlen(message_buf)); /* send buffer to client */
							}else
							{	
								SSL_write(client_ssl,"ERR",3); /* return error */
							}

							custom_free(message_buf); /* cleanup */

						}else
						{
							/* message buffer was NULL */
							SSL_write(client_ssl,"ERR",3); /* return error */
						}
			
					} /* REQUEST_MESSAGES */
					else if(message_purpose == SEND_MESSAGE)
					{	
						byte* message_recipient = SSCS_object_string(serialized_object,"recipient"); /* retrieve recipient from serialized object */
						if(message_recipient == NULL)
						{
							logerr("user wants to send message, but recipient is not specified");	
							SSCS_release(&serialized_object);
							goto END_CONN;
						}	
					
						string_remove_newline(message_recipient); /* remove newline if applicable */
					
						byte* contains_sender_buf = SSCS_object_string(serialized_object,"sender");	
						if(contains_sender_buf != NULL)
						{
							/* user may have tried to spoof sender */
							custom_free(contains_sender_buf);
							custom_free(message_recipient);
							SSCS_release(&serialized_object);	
							goto END_CONN;
						}	
						
						SSCS_object_add_data(serialized_object,"sender",user_auth_name_stack,strlen(user_auth_name_stack)); /* add sender to serialized object (logged in user) */

						logdbg("Buffering message from %s to %s",user_auth_name_stack,message_recipient);
						#ifdef SSCS_OUTPUT_LIVE
							logdbg("Message length %d -- content -- %s",strlen(serialized_object->buf_ptr),serialized_object->buf_ptr);
						#endif

						byte* nterm_buf = SSCS_object_encoded(serialized_object);
				
						if(store_message_to_db(db_conn,message_recipient,nterm_buf) != 0) /* store message in db */
						{
							/* failed to store message */
							logerr("Error storing message");
							SSL_write(client_ssl,"ERR",3);
						}else
						{
							/* successfully stored message */
							SSL_write(client_ssl,"ACK",3);
						}
						custom_free(nterm_buf);
						custom_free(message_recipient);	 /* cleanup */
						
					} /* SEND_MESSAGE */

					SSCS_release(&serialized_object); /* cleanup */
					fflush(stdout);
					fflush(stderr);
				} /* AUTH_WHILE_LOOP */
			}else
			{
				/* user failed to auth */
				logerr("User %s failed to authenticate.",user_auth_name);

				SSCS_freehash(&user_verified_hash);
				SSCS_release(&serialized_object);
				custom_free(user_auth_key);
				custom_free(user_auth_name);
				goto END_CONN;	
			}
		} /* AUTHENTICATE_USER */
		else{
			logerr("Message without a purpose received, exiting..");
			SSCS_release(&serialized_object);
			goto END_CONN;
		}

		SSCS_release(&serialized_object); /* cleanup the Serialized Object */
		
		/* flush out logfile & other */
		fflush(stdout); 
		fflush(stderr);
		
	}
	return 0;

FAILURE:	
	logerr(" Error handling client, (goto FAILURE)");
	return -1;
END_CONN:
	/* cleanup */
	logdbg("Ending client session");
	BIO_free(client_bio);
	SSL_free(ssl_client);
	close(client_internal);
	mysql_close(db_conn);
	custom_free(usr_buf);
	custom_free(client_info_void);
	#ifdef SSCS_CLIENT_FORK
		exit(0);
	#else
		pthread_exit(0);
	#endif
}
