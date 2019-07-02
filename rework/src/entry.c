/*
 * Start point of reworked SimpleSecureChat-Server 
 */

#include "entry.h" /* all neccessary headers */

/* 
 * Coding Standards:
 * All Custom functions must return 0 on success.
 * All Custom functions should be multiple words seperated by a
 * '_' ex: add_alpha_to_beta(a,b) and should explain the use of the said function.
 */

/* Global Variables */

int listening_socket = 0; /* global listening socket so that this socket can be closed from a signal handler */

SCONFIG* global_config = NULL; /* config file ptr so all functions that require external config do not need to be passed this pointer */

int main(int argc,char** argv[]) /* entry point */
{
	global_config = load_config();	
	if(sconfig_get_int(global_config,"SSCS_LOGTOFILE") == 1) /* check if we are logging to file */
	{
		byte* log_file_path = sconfig_get_str(global_config,"SSCS_LOGFILE"); /* get log file path */
		if(log_file_path == NULL){ /* could not find string in config */
			logerr("could not find log file path in configuration"); /* default for logerr() is to write to stderr */
			return -1;	
		}
		FILE* stdout_redef = freopen(log_file_path,"a+",stdout);
		FILE* stderr_redef = freopen(log_file_path,"a+",stderr);

		log_set_fd(stdout_redef,stderr_redef); /* redirect logs to the file var(log_file_path) */
	}
	
	/* register signal handlers for SIGINT(CTRL-C) & SIGCHLD(Child Zombie Process) */
	signal(SIGINT,ssc_signal_handler);	
	signal(SIGCHLD,child_exit_handler);
	
	CHKFAIL(ssc_init_db()); /* init MySQL DB */

	CHKFAIL(ssc_init_openssl()); /* init OpenSSL */
	
	/* create ssl context var(listen_context) */
	SSL_CTX* listen_context = ssl_create_context();
	CHKFAIL(ssl_configure_context(listen_context));
	EXISTS(listen_context);

	/* Start listening socket */
	listening_socket = ip_listen_port(5050);
	
	/* Start accepting inbound connections */
	
	struct sockaddr_in client_conn; /* reused object to temporarily hold connection info */
	uint client_conn_len = sizeof(client_conn); /* get client_conn length */
	int client_internal = 0; /* reused object to temporarily hold client socket */
	while(1)
	{
		client_internal = accept(listening_socket, (struct sockaddr*)&client_conn, &client_conn_len); /* accept incoming connections */

		#ifdef    SSCS_LOG_IP_ADDRESSES
		loginfo("Inbound Connection from %s:%i",inet_ntoa(client_conn.sin_addr),ntohs(client_conn.sin_port));
		#endif /* SSCS_LOG_IP_ADDRESSES */
		
		/* Create HANDLER_DATA object to pass to thread or new process(fork) to handle client */
		HANDLER_DATA* handler_data = custom_malloc(sizeof(HANDLER_DATA));	
		handler_data->client_conn = client_internal;
		handler_data->ssl_ctx = listen_context;
		EXISTS(handler_data); /* check that object exists */
	
		#ifdef    SSCS_CLIENT_FORK /* If compiled to fork() for every client, then fork() */

		pid_t process_id = fork();	

		if(process_id == 0)ssc_handle_client(handler_data); /* pass client info to new handler */

		custom_free(handler_data); /* free handler_data because fork() copies the complete memory, so this memory is not used anymore */

		#else
		
		pthread_t thread_id;
		if( pthread_create(&thread_id,NULL,ssc_handle_client,handler_data) ) /* Spawn thread to handle client */
		{
				/* do this if we cant spawn the thread */
				logerr("Failed to create thread to handle client (%s)",strerror(errno));	
				custom_free(handler_data); /* free handler data */
				goto FAILURE;
		}	
		
		#endif /* FORK / THREAD */
	}

	loginfo("Server Main Process exiting... ");
	close(listening_socket);
	SSL_CTX_free(listen_context);
	ssc_cleanup_openssl();
	sconfig_close(global_config);
	return 0;

FAILURE:
	logerr("Error occurred,exiting.. (goto FAILURE)");
	exit(EXIT_FAILURE);
}


