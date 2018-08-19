
#include "isc.h"

/* NOT COMPLETD DO NOT CALL ANY FUNCTIONS FROM THIS FILE */

/* INTER SERVER COMMUNTICATION BASED ON A TRUST SYSTEM */

#define stmterr(x) cerror("mysql stmt error - %s",mysql_stmt_error(x))

int isc_check_exists(MYSQL* db, byte* srvname){ 

	if(!srvname)cexit("passed NULL ptr as srvname");

	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt)return 1;

	char* query_base = "SELECT SRVID FROM SERVER_ASSOC WHERE srvname = ?";
	
	if(mysql_stmt_prepare(stmt,query_base,strlen(query_base))){
		cerror("stmt prepare failed (%s)",mysql_stmt_error(stmt));
		goto FAILURE;	
	}	

	MYSQL_BIND bind[1];
	memset(bind,0,sizeof(bind));

	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = srvname;
	bind[0].buffer_length = strlen(srvname);

	if(mysql_stmt_bind_param(stmt,bind)){
		goto FAILURE;
	}

	if(mysql_stmt_execute(stmt)){
		goto FAILURE;
	}

	if(!mysql_stmt_fetch(stmt)){
		/* server exists */
		mysql_stmt_close(stmt);	
		return 1;
	}
	else{
		/* server does not exist */
		mysql_stmt_close(stmt);	
		return 0;
	}


FAILURE:
	if(stmt){
		stmterr(stmt);
		mysql_stmt_close(stmt);
	}
	return 1;
}
int isc_reg_server(MYSQL* db, byte* ip, byte* srvname, byte* server_public_cert_b64){ /* (0)Success (ELSE)Failure */

	/* The purpose of this function is to add an associate server to the DB after checking that one does not exist under the name already (NOTE THAT THE INPUT TO THIS FUNCTION IS TRUSTED)*/

	debuginfo();
	
	cdebug("Trying to register server (%s,%s)",srvname,ip);

	if(isc_check_exists(db,srvname) == 1){
		cdebug("Could not register server(%s,%s) - Server already exists",srvname,ip);
		return -1;
	}

	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt){
		cerror("Failed to init mysql stmt");	
		return -2;
	}
	char* query_base = "INSERT INTO SERVER_ASSOC VALUES(NULL,?,?,?)";

	if(mysql_stmt_prepare(stmt,query_base,strlen(query_base))){
		cerror("Could not prepare mysql stmt (%s)",mysql_stmt_error(stmt));	
		mysql_stmt_close(stmt);
		return -3;
	}

	MYSQL_BIND bind[3];	
	memset(bind,0,sizeof(bind));

	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = srvname;
	bind[0].buffer_length = strlen(srvname);

	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = ip;
	bind[1].buffer_length = strlen(ip);

	bind[2].buffer_type = MYSQL_TYPE_STRING;
	bind[2].buffer = server_public_cert_b64;
	bind[2].buffer_length = strlen(server_public_cert_b64);

	if(mysql_stmt_bind_param(stmt,bind)){
		cerror("Failed to bind values to query (%s)",mysql_stmt_error(stmt));	
		mysql_stmt_close(stmt);
		return -4;
	}

	if(mysql_stmt_execute(stmt)){
		cerror("Failed to execute query (%s)",mysql_stmt_error(stmt));	
		mysql_stmt_close(stmt);
		return -5;
	}

	/* CLEANUP */
	mysql_stmt_close(stmt);

	return 0;
}

int isc_get_srvid(MYSQL* db, byte* srvname){ /* (-1)Failure - Else is srvid */
	debuginfo();

	if(!srvname)return -1;
	if(isc_check_exists(db,srvname) == 0){
		cerror("Server %s not found in DB",srvname);	
		return -1;
	}
	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt){
		cerror("failed to init mysql stmt");	
		return -1;
	}
	char* query_base = "SELECT SRVID FROM SERVER_ASSOC WHERE SRVNAME = ?";
	if(mysql_stmt_prepare(stmt,query_base,strlen(query_base))){
		goto FAILURE;
	}

	MYSQL_BIND bind[1];
	memset(bind,0,sizeof(bind));

	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = srvname;
	bind[0].buffer_length = strlen(srvname);

	if(mysql_stmt_bind_param(stmt,bind)){
		goto FAILURE;
	}

	MYSQL_BIND result[1];
	memset(result,0,sizeof(result));
	
	int srvid = -1;

	result[0].buffer_type = MYSQL_TYPE_LONG;
	result[0].buffer = &srvid;

	if(mysql_stmt_execute(stmt)){
		goto FAILURE;
	}

	if(mysql_stmt_bind_result(stmt,result)){
		goto FAILURE;
	}

	if(mysql_stmt_store_result(stmt)){
		goto FAILURE;
	}

	if(mysql_stmt_fetch(stmt)){
		goto FAILURE;
	}
	
	/* CLEANUP */
	mysql_stmt_close(stmt);
	return srvid;

	/* FAILURE LABEL FOR JMP */
FAILURE:
	if(stmt){
		stmterr(stmt);
		mysql_stmt_close(stmt);
	}
	return -1;

}

void isc_rm_server(MYSQL* db, int srvid){ 
	debuginfo();
}

byte* isc_get_user_packet(MYSQL* db, byte* username){
	debuginfo();
	char* newline = strchr(username,'\n');
	if(newline)*newline = 0;
	
	MYSQL_STMT* stmt = mysql_stmt_init(db);
	if(!stmt){
		cerror("failed to init stmt");
		return NULL;	
	}

	char* query_base = "SELECT SRVNAME,IP,B64CERT FROM SERVER_ASSOC";

	if(mysql_stmt_prepare(stmt,query_base,strlen(query_base)))goto FAILURE;	

	if(mysql_stmt_execute(stmt))goto FAILURE;
	
	MYSQL_BIND result[1];
	size_t srvname_l = 0;
	result[0].buffer_type=MYSQL_TYPE_STRING;
	result[0].length=&srvname_l;
	
	if(mysql_stmt_bind_result(stmt,result))goto FAILURE;	
	
	if(mysql_stmt_store_result(stmt))goto FAILURE;


	
	
FAILURE:
	if(stmt){
		stmterr(stmt);
		mysql_stmt_close(stmt);
	}
	return NULL;

}
