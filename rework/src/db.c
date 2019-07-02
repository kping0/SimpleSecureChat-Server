#include "db.h"

extern SCONFIG* global_config;

int cust_mysql_query(MYSQL* con, byte* query) /* query db with error checking */
{
	int retval = mysql_query(con,(char*)query); 
	if(retval)
	{
		exit_mysql_err(con);
	}
	return retval;
} /* cust_mysql_query */

void exit_mysql_err(MYSQL* con)
{
	logerr("%s",mysql_error(con));
	mysql_close(con);
	do_exit();
} /* exit_mysql_err() */

int ssc_init_db()
{
	mysql_library_init(0,NULL,NULL);

	logdbg("MySQL version: %s",mysql_get_client_info()); /* output debug info */

	MYSQL* con = mysql_init(NULL); /* create MYSQL object */
	if(con == NULL)
	{
		/* failed to allocate mysql object */
		logerr("failed to allocate mysql object (%s)",mysql_error(con));
		do_exit();	
	}
	/* get server details from config */
	byte* server_hostname = sconfig_get_str(global_config,"server_hostname");
	if(server_hostname == NULL)
	{
		logerr("failed to retrieve server_hostname from the configfile");
		mysql_close(con);
		do_exit();
	}

	byte* server_username = sconfig_get_str(global_config,"server_username");
	if(server_username == NULL)	
	{
		logerr("failed to retrieve server_username from the configfile");
		custom_free(server_hostname);
		mysql_close(con);
		do_exit();
	}
	
	byte* server_password = sconfig_get_str(global_config,"server_password"); 
	if(server_password == NULL)
	{
		logerr("failed to retrieve server_password from the configfile");
		custom_free(server_hostname);
		custom_free(server_username);
		mysql_close(con);
		do_exit();
	}

	/* connect to the server */
	if( !mysql_real_connect(con, server_hostname, server_username, server_password, NULL, 0, NULL, 0) )
	{
		custom_free(server_hostname);
		custom_free(server_username);
		custom_free(server_password);	
		exit_mysql_err(con);
	}

	/* check if database exists */
	if(mysql_query(con, "use SSCServerDB"))
	{
		loginfo(" MySQL-db 'SSCServerDB' not found, is SSCS running for the first time ? (trying to create db)");
		/* create database */
		if(mysql_query(con, "CREATE DATABASE SSCServerDB"))
		{
			logerr("failed to create DB 'SSCServerDB'");
			custom_free(server_hostname);
			custom_free(server_username);
			custom_free(server_password);
			exit_mysql_err(con);
		}
		
		/* select (use) database */
		if(mysql_query(con, "use SSCServerDB"))
		{
			logerr("failed to 'use SSCServerDB'");
			custom_free(server_hostname);
			custom_free(server_username);
			custom_free(server_password);
			exit_mysql_err(con);
		}
	}
	
	loginfo("started session with mysql-db %s:%s", mysql_get_client_info(), server_hostname);
	
	/* create neccessary tables for SSCS */
	char message_table_query1[] = "CREATE TABLE IF NOT EXISTS MESSAGES(MSGID INT AUTO_INCREMENT PRIMARY KEY,RECVUID INT NOT NULL,MESSAGE TEXT NOT NULL)";	
	
	char known_users_table_query2[] = "CREATE TABLE IF NOT EXISTS KNOWNUSERS(UID INT AUTO_INCREMENT PRIMARY KEY, USERNAME TEXT NOT NULL,RSAPUB64 TEXT NOT NULL, RSALEN INT NOT NULL, SHA256 TEXT NOT NULL, SALT TEXT NOT NULL)";	
	
	char server_associated_table_query3[] = "CREATE TABLE IF NOT EXISTS SERVER_ASSOC(SRVID INT AUTO_INCREMENT PRIMARY KEY, SRVNAME TEXT NOT NULL, IP TEXT NOT NULL, B64CERT TEXT NOT NULL)";

	/* create messages table */
	if( mysql_query(con, message_table_query1) )
	{
		/* failed to create table */
		logerr("failed to create message table");
		custom_free(server_hostname);
		custom_free(server_username);
		custom_free(server_password);	
		exit_mysql_err(con);
	}

	/* create known users table */
	if( mysql_query(con, known_users_table_query2) )	
	{
		/* failed to create table */
		logerr("failed to create users table");
		custom_free(server_hostname);
		custom_free(server_username);
		custom_free(server_password);	
		exit_mysql_err(con);
	}
	
	/* create associated servers table */
	if( mysql_query(con, server_associated_table_query3) )
	{
		/* failed to create table */
		logerr("failed to create associated servers table");
		custom_free(server_hostname);
		custom_free(server_username);
		custom_free(server_password);	
		exit_mysql_err(con);
	}	

	/* cleanup */
	custom_free(server_hostname);
	custom_free(server_username);	
	custom_free(server_password);
	mysql_close(con);

	return 0;
} /* ssc_init_db */


MYSQL* get_db_handle() /* get handle to database */
{
	/* create con obj */
	MYSQL* con = mysql_init(NULL);
	if(con == NULL)	
	{
		logerr("failed to allocate mysql con object (%s)", mysql_error(con));
		do_exit();
	}

	/* retrieve server hostname */
	byte* server_hostname = sconfig_get_str(global_config,"server_hostname");
	if(server_hostname == NULL)
	{
		logerr("failed to retrieve server_hostname from the configfile");
		mysql_close(con);
		do_exit();
	}

	/* retrieve server username */
	byte* server_username = sconfig_get_str(global_config,"server_username");
	if(server_username == NULL)	
	{
		logerr("failed to retrieve server_username from the configfile");
		custom_free(server_hostname);
		mysql_close(con);
		do_exit();
	}
	
	/* retrieve server password */
	byte* server_password = sconfig_get_str(global_config,"server_password"); 
	if(server_password == NULL)
	{
		logerr("failed to retrieve server_password from the configfile");
		custom_free(server_hostname);
		custom_free(server_username);
		mysql_close(con);
		do_exit();
	}

	

	/* connec to server */
	if( !mysql_real_connect(con, server_hostname, server_username, server_password, "SSCServerDB", 0, NULL, 0) )
	{
		logerr("failed to connect to server");
		custom_free(server_hostname);
		custom_free(server_username);	
		custom_free(server_password);
		exit_mysql_err(con);		
	}
		
	/* cleanup */
	custom_free(server_hostname);
	custom_free(server_username);	
	custom_free(server_password);
	
	return con;
} /* get_db_handle() */

int check_user_exists(byte* username,MYSQL* db) /* check if user exists */
{
	MYSQL_STMT* stmt = mysql_stmt_init(db); /* create a mysql statement */
	if(!stmt)
	{
		logerr("failed to allocate stmt");
		return -1;
	}

	char statement[] = "SELECT UID FROM KNOWNUSERS WHERE username=?";

	/* bind statment to stmt */
	if( mysql_stmt_prepare(stmt, statement, strlen(statement)) ) goto FATAL_ERR;

	/* create bind that contains username */
	MYSQL_BIND bind[1];
	memset(bind, 0x0, sizeof(bind)); /* set all to zero so that non-set options do NOT contain random values */

	bind[0].buffer_type = MYSQL_TYPE_STRING;	
	bind[0].buffer = username;
	bind[0].buffer_length = strlen(username);

	/* bind input to stmt */	
	if(mysql_stmt_bind_param(stmt, bind)) goto FATAL_ERR;

	/* execute statement */
	if( mysql_stmt_execute(stmt) ) goto FATAL_ERR;
	
	/*
	 * Figure out if the user exists or not
	 */
	
	if( !mysql_stmt_fetch(stmt) )
	{
		/* user exists */
		mysql_stmt_close(stmt);
		return 1;
	}	
	else
	{
		/* user does NOT exist */
		mysql_stmt_close(stmt);	
		return 0;
	}
FATAL_ERR:
	logerr("stmt error occurred (%s)",mysql_stmt_error(stmt));
	mysql_stmt_close(stmt);	
	return -1;
} /* check_user_exists() */

int add_user_to_db(byte* username, byte* base64_rsa, size_t rsa_len, byte* auth_key, MYSQL* db)
{
	/* init variables */
	SSCS_HASH* hash = NULL;

	MYSQL_BIND bind[5];
	memset(bind, 0x0, sizeof(bind));

	MYSQL_STMT* stmt = mysql_stmt_init(db); /* create a mysql-stmt obj */	
	if(!stmt)	
	{
		logerr("failed to init a stmt");
		mysql_close(db);
		do_exit();
	}
	
	char statement[] = "INSERT INTO KNOWNUSERS VALUES(NULL,?,?,?,?,?)";
	
	/* prepare stmt with statement */
	if( mysql_stmt_prepare(stmt, statement, strlen(statement)) ) goto FATAL_ERR;

	hash = SSCS_createhash(auth_key, strlen(auth_key)); /* hash the auth_key */
	
	/* fill the MYSQL_BIND bind with all our user information: username,public key, rsa_len, salt, and hash */
	bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = username;
        bind[0].buffer_length = strlen(username);

        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = base64_rsa;
        bind[1].buffer_length = strlen(base64_rsa);

        bind[2].buffer_type = MYSQL_TYPE_LONG;
        bind[2].buffer = &rsa_len;
        bind[2].buffer_length = sizeof(size_t);

        bind[3].buffer_type = MYSQL_TYPE_STRING;
        bind[3].buffer = hash->hash;
        bind[3].buffer_length = hash->hash_len;

        bind[4].buffer_type = MYSQL_TYPE_STRING;
        bind[4].buffer = hash->salt;
        bind[4].buffer_length = hash->salt_len;
	
	/* bind our bind object to our stmt */
	if( mysql_stmt_bind_param(stmt, bind) ) goto FATAL_ERR;
	
	/* execute the filled stmt */
	if( mysql_stmt_execute(stmt) ) goto FATAL_ERR;
	
	/*
	 * By now the user has been added (if no errors occurred) 
 	 */
	mysql_stmt_close(stmt); /* cleanup */
	SSCS_freehash(&hash);
	
	return 0;	

FATAL_ERR:
	logerr("fatal error has occurred");
	/* place to jump to when an stmt error occurred */
	if(stmt)
	{
		logerr("stmt error occurred (%s)",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
	}
	if(hash)SSCS_freehash(&hash);
	return -1; 

} /* add_user_to_db() */

int get_user_uid(byte* username, MYSQL* db) /* return user uid */
{
		
	MYSQL_BIND bind[1];	
	MYSQL_BIND result[1];
	int user_uid = -1;

	if(!username)
	{
		logerr("username not supplied. Fatal");
		mysql_close(db);
		do_exit(); /* exit if no username was supplied (to be on the safe side) */
	}
		
	/* allocate mysql statment obj */
	MYSQL_STMT* stmt = mysql_stmt_init(db); /* init stmt */
	if(!stmt)	
	{
		/* no memory to allocate */
		logerr("failed to allocate mysql stmt");
		mysql_close(db);
		do_exit();
	}

	/* prepare mysql stmt */
	char* statement = "SELECT UID FROM KNOWNUSERS WHERE USERNAME = ?";
	if( mysql_stmt_prepare(stmt, statement, strlen(statement)) ) goto FATAL_ERR;

	/* prepare insert bind */
	memset(bind,0x0,sizeof(bind)); /* cleanup memory in bind obj */
	
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = username;
	bind[0].buffer_length = strlen(username);
	
	if( mysql_stmt_bind_param(stmt, bind) ) goto FATAL_ERR; /* bind insert to query */

	if( mysql_stmt_execute(stmt) )goto FATAL_ERR; /* execute statement */

	/* prepare result bind */
	memset(result,0x0,sizeof(result));
	
	result[0].buffer_type = MYSQL_TYPE_LONG;
	result[0].buffer = &user_uid;

	if( mysql_stmt_bind_result(stmt, result) ) goto FATAL_ERR; /* bind result to query */

	if( mysql_stmt_store_result(stmt) ) goto FATAL_ERR; /* retrieve result */

	if( mysql_stmt_fetch(stmt) ) /* read results from stmt obj */
	{
		logerr("failed to retrieve user uid, maybe user does not exist ? (%s)",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return -1;
	}
	else
	{
		mysql_stmt_close(stmt);
		return user_uid;
	}
FATAL_ERR: /* general cleanup to reuse the same code */
	logerr("fatal error has occurred");
	if(stmt)
	{
		logerr("stmt error (%s)",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
	}
	if(db)mysql_close(db);	
	do_exit();
	return -1;
} /* get_user_uid() */

int store_message_to_db(MYSQL* db,byte* recipient, byte* message) /* add message to db. NOTE that message has to be a NULL terminated string! */
{
	/* initalize variables */
	int recipient_uid;
	MYSQL_BIND bind[2];
	char* statement = "INSERT INTO MESSAGES VALUES(NULL,?,?)";
	MYSQL_STMT* stmt = NULL;

	/* check if recipient exists */
	if( check_user_exists(recipient,db) != 1)
	{
		logerr("user does not exist.");
		goto FATAL_ERR;
	}

	/* allocate memory for stmt */
	if( !(stmt = mysql_stmt_init(db)) )
	{
		logerr("failed to allocate memory for stmt");
		goto FATAL_ERR;
	}
	
	/* prepare mysql stmt */
	if( mysql_stmt_prepare(stmt, statement, strlen(statement)) )goto FATAL_ERR;

	/* get uid for user */
	recipient_uid = get_user_uid(recipient,db);
	
	/* prepare insert bind */
	memset(bind, 0x0, sizeof(bind));

	/* insert bind recipient uid */
	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = &recipient_uid;
	bind[0].buffer_length = sizeof(int);
	
	/* insert bind message */
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = message;
	bind[1].buffer_length = strlen( (const char*)message );

	/* bind insert bind to statement */
	if( mysql_stmt_bind_param(stmt, bind) )goto FATAL_ERR;

	/* execute statement */
	if( mysql_stmt_execute(stmt) )goto FATAL_ERR;

	/* if we reach here without error, message was successfully added */	

	mysql_stmt_close(stmt);
	return 0;
	
FATAL_ERR: /* general cleanup */
	logerr("fatal error has occurred");
	if(stmt)
	{
		logerr("stmt error (%s)",mysql_stmt_error(stmt));	
		mysql_stmt_close(stmt);
	}
	return -1;
}

byte* get_encoded_public(byte* username, MYSQL* db)
{
	if(!username || !db) return NULL;

	string_remove_newline(username); /* remove exccess newline characters from username string */

	/* initalize variables */
	MYSQL_STMT* stmt = NULL;
	char* statement = "SELECT RSAPUB64,RSALEN FROM KNOWNUSERS WHERE USERNAME = ? LIMIT 1";	
	byte* base64_rsa = NULL;	
	size_t rsa_len = 0;
	size_t base64_rsa_len = 0;
	int mysql_stmt_fetch_chk = 0; 
	MYSQL_BIND bind[1];
	MYSQL_BIND result[2];
	

	if( (stmt = mysql_stmt_init(db)) == NULL) goto FATAL_ERR; /* allocate mysql statement */
	
	if( mysql_stmt_prepare(stmt, statement, strlen(statement))  ) goto FATAL_ERR; /* prepare mysql stmt */

	/* prepare insert bind */	
	memset(bind, 0x0, sizeof(bind));
	
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = username;
	bind[0].buffer_length = strlen(username);

	if( mysql_stmt_bind_param(stmt,bind) ) goto FATAL_ERR; /* link insert bind to stmt */

	if( mysql_stmt_execute(stmt) ) goto FATAL_ERR; /* execute statment */

	/* prepare result bind */
	memset(result, 0x0, sizeof(result));

	result[0].buffer_type = MYSQL_TYPE_STRING;
	result[0].length = &base64_rsa_len;

	result[1].buffer_type = MYSQL_TYPE_LONG;
	result[1].buffer = &rsa_len;
	
	if( mysql_stmt_bind_result(stmt, result) ) goto FATAL_ERR; /* bind to stmt */	

	if( mysql_stmt_store_result(stmt) ) goto FATAL_ERR; /* store result locally */	
	
	/* fetch first set of results */
	mysql_stmt_fetch_chk = mysql_stmt_fetch(stmt);

	if( mysql_stmt_fetch_chk && !(mysql_stmt_fetch_chk == MYSQL_DATA_TRUNCATED) ) goto FATAL_ERR; /* check for errors */

	if(base64_rsa_len > 0)	
	{
		base64_rsa = custom_malloc(base64_rsa_len); /* allocate buffer to hold pubkey */
		memset(result,0x0,sizeof(result)); /* reset result */
		
		result[0].buffer = base64_rsa;
		result[0].buffer_length = base64_rsa_len;
	
		mysql_stmt_fetch_column(stmt, result, 0, 0); /* refetch the pubkey */
	}	
	else
	{
		/* error has occurred */
		logdbg(" base64_rsa_len <= 0, maybe user \"%s\" does not exist ?",username); 
		goto FATAL_ERR;	
	}

	logdbg("b64-pubkey: %s || pubkey-len: %i",base64_rsa,rsa_len);

	/* 
	 * put all queried values into a serialized structure to return 
 	 */

	int message_purpose = REQUEST_USER_PUBLIC_RESPONSE;
	
	sscso* ret_obj = SSCS_object();
		
	SSCS_object_add_data(ret_obj, "msgp", &message_purpose, sizeof(int));
	SSCS_object_add_data(ret_obj, "b64rsa", base64_rsa, base64_rsa_len);	
	SSCS_object_add_data(ret_obj, "rsalen", rsa_len, sizeof(int));

	byte* return_string = SSCS_object_encoded(ret_obj); 
	
	/* cleanup */
	SSCS_release(&ret_obj);
	custom_free(base64_rsa);
	mysql_stmt_close(stmt);

	return return_string;

FATAL_ERR: /* general cleanup */
	logerr("fatal error has occurred");	

	if(stmt)
	{
		logerr("stmt error (%s)",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
	}	

	if(base64_rsa)custom_free(base64_rsa);

	return NULL;
} /* get_encoded_public() */

byte* get_enc_user_messages(byte* username, MYSQL* db) /* return an encoded (serialized) object that conatines the users encrypted messages */
{		
	if( !username || !db) return NULL;

	/* check if the user exists */
	if( check_user_exists(username, db) != 1)
	{
		logerr("user does not exist.");
		goto FATAL_ERR;
	}

	/* initalize variables */	
	sscsl* list = NULL;
	byte* message_buf = NULL;
	byte* return_allocated_string = NULL;

	int user_uid = get_user_uid(username, db);
	size_t message_length = 0;
	int mysql_stmt_fetch_chk;
	char* statement = "SELECT MESSAGE FROM MESSAGES WHERE RECVUID = ?"; /* query template for selecting the messages */
	char* statement2 = "DELETE FROM MESSAGES WHERE RECVUID = ?"; /* query template to delete the selected messages */

	MYSQL_BIND bind[1];		
	MYSQL_BIND bind2[1];
	MYSQL_BIND result[1];
	MYSQL_STMT* stmt = NULL;
	MYSQL_STMT* stmt2 = NULL;

	
	if( (stmt = mysql_stmt_init(db)) == NULL) goto FATAL_ERR; /* allocate memory for stmt */

	if( mysql_stmt_prepare(stmt, statement, strlen(statement)) ) goto FATAL_ERR; /* prepare stmt with template */
	
	/* prepare insert bind */	
	memset(bind, 0x0, sizeof(bind) );

	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = &user_uid;
	bind[0].buffer_length = sizeof(int);

	if( mysql_stmt_bind_param(stmt, bind) ) goto FATAL_ERR; /* bind bind to stmt */

	if( mysql_stmt_execute(stmt) ) goto FATAL_ERR; /* execute stmt */

	/* prepare result bind */	
	memset(result, 0x0, sizeof(result) );
	
	result[0].buffer_type = MYSQL_TYPE_STRING;
	result[0].buffer_length = &message_length;

	if( mysql_stmt_bind_result(stmt, result) ) goto FATAL_ERR; /* bind result to stmt */

	if( mysql_stmt_store_result(stmt) ) goto FATAL_ERR; /* store result locally */

	list = SSCS_list();	

	while(1) /* loop to retrieve messages one by one */
	{
		message_length = 0;	
		mysql_stmt_fetch_chk = mysql_stmt_fetch(stmt); 
		message_buf = NULL;	

		if( mysql_stmt_fetch_chk == MYSQL_NO_DATA ) /* we have all the messages */
		{
			mysql_stmt_close(stmt);
			break;
		}

		if( mysql_stmt_fetch_chk && !(mysql_stmt_fetch_chk == MYSQL_DATA_TRUNCATED) )goto FATAL_ERR; /* error occurred in query */

		if(message_length > 0)
		{
			message_buf = custom_malloc(message_length); /* allocate message buffer */
			memset(result, 0x0, sizeof(result)); /* reset result to avoid errors */

			result[0].buffer = message_buf;
			result[0].buffer_length = message_length;
			
			mysql_stmt_fetch_column(stmt, result, 0, 0);			
		}
		else
		{
			mysql_stmt_close(stmt);	
			break;
		}
		
		SSCS_list_add_data(list, message_buf, message_length); /* add message to list */

		custom_free(message_buf); /* cleanup */

		/* rinse and repeat until a 'break' occurs */
	}

	return_allocated_string = SSCS_list_encoded(list); /* pointer that we WILL return */
	
	SSCS_list_release(&list); /* cleanup */

	stmt = NULL;

	/*
	 * Delete the messages we just read into a heap object from the DB 
	 */

	if( (stmt2 = mysql_stmt_init(db)) == NULL) goto FATAL_ERR;	

	if( mysql_stmt_prepare(stmt2, statement2, strlen(statement2)) ) goto FATAL_ERR;	/* prepare stmt */

	/* prepare insert bind2 */
	memset(bind2, 0x0, sizeof(bind2));

	bind2[0].buffer_type = MYSQL_TYPE_LONG;
	bind2[0].buffer = &user_uid;
	bind2[0].buffer_length = sizeof(int);

	if( mysql_stmt_bind_param(stmt, bind) ) goto FATAL_ERR; /* bind bind to stmt */

	if( mysql_stmt_execute(stmt) ) goto FATAL_ERR; /* exec stmt */

	/*
	 * at this point no errors have occurred and we can return the list object 
	 */

	mysql_stmt_close(stmt2); /* cleanup */

	return return_allocated_string;
	
FATAL_ERR: /* reused cleanup code */
	logerr("fatal error has occurred");	
	
	if(stmt)
	{
		logerr("stmt error (%s)",mysql_stmt_error(stmt));	
		mysql_stmt_close(stmt);
	}
	if(stmt2)
	{
		logerr("stmt2 error (%s)",mysql_stmt_error(stmt2));
		mysql_stmt_close(stmt2);
	}

	if(list) SSCS_list_release(&list);
	
	if(return_allocated_string) custom_free(return_allocated_string);
	
	return NULL;	
}

SSCS_HASH* get_user_auth_hash(byte* username, MYSQL* db)
{
	if( !username || !db ) return NULL;

	/* init variables */	
	MYSQL_STMT* stmt = NULL;	
	char* statement = "SELECT SHA256,SALT FROM KNOWNUSERS WHERE USERNAME = ? LIMIT 1"; /* query template to retrieve sha256 and salt */
	MYSQL_BIND bind[1];
	MYSQL_BIND result[2];
	size_t hash_len, salt_len = 0;
	int mysql_stmt_fetch_chk = 0;

	if( (stmt = mysql_stmt_init(db)) ) goto FATAL_ERR; /* allocate statement */

	if( mysql_stmt_prepare(stmt, statement, strlen(statement)) ) goto FATAL_ERR;

	/* prepare insert bind */
	memset(bind, 0x0, sizeof(bind));
	
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = username;
	bind[0].buffer_length = strlen(username);

	if( mysql_stmt_bind_param(stmt, bind) ) goto FATAL_ERR; /* bind bind to stmt */

	/* execute stmt */
	if( mysql_stmt_execute(stmt) ) goto FATAL_ERR;

	/* prepare result bind */
	memset(result, 0x0, sizeof(result));

	result[0].buffer_type = MYSQL_TYPE_STRING;
	result[0].buffer_length = &hash_len;
	
	result[1].buffer_type = MYSQL_TYPE_STRING;
	result[1].buffer_length = &salt_len;

	if( mysql_stmt_bind_result(stmt,result) ) goto FATAL_ERR; /* bind result to stmt */

	if( mysql_stmt_store_result(stmt) ) goto FATAL_ERR; /* store result locally */	

	mysql_stmt_fetch_chk = mysql_stmt_fetch(stmt); /* fetch result */
		
	if(mysql_stmt_fetch_chk && !(mysql_stmt_fetch_chk == MYSQL_DATA_TRUNCATED) ) goto FATAL_ERR; /* error checking the return value of mysql_stmt_fetch() */
	
	/* allocate the returned hash object and populate it */
	SSCS_HASH* hash = custom_malloc(sizeof(SSCS_HASH));	 

	hash->hash = custom_malloc(hash_len); /* allocate hash buffer */
	hash->hash_len = hash_len;
	hash->salt = custom_malloc(salt_len); /* allocate salt buffer */
	hash->salt_len = salt_len;

	/* retrieve hash from results */
	memset(result, 0x0, sizeof(result));
	
	result[0].buffer_type = MYSQL_TYPE_STRING;
	result[0].buffer = (hash->hash);
	result[0].buffer_length = hash_len;

	mysql_stmt_fetch_column(stmt, result, 0, 0); 


	/* retrieve salt from results */
	memset(result, 0x0, sizeof(result)); 
	
	result[0].buffer_type = MYSQL_TYPE_STRING;
	result[0].buffer = (hash->salt);
	result[0].buffer_length = salt_len;

	mysql_stmt_fetch_column(stmt, result, 0, 0);

	
	mysql_stmt_close(stmt); /* cleanup */
	
	return hash;	

FATAL_ERR:
	logerr("fatal error has occurred");

	if(stmt)
	{
		logerr("stmt error (%s)",mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
	}	
	return NULL;
}

