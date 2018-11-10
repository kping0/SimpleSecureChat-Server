#include "read_config.h"

static void get_from_stdin(byte* buf, size_t buf_len)
{
	size_t i = 0;
	while(i+1 != buf_len)
	{
		buf[i] = fgetc(stdin);
		if(buf[i] == '\n')
		{
			buf[i] = 0x0;
			return;
		}
	}
	buf[i] = 0x0;
	return;
}

SCONFIG* load_config()
{
	#ifndef SSCS_CONFIG_SET_ABSOLUTE_PATH	

		/* dynamic path (HOME + Folder prefix ) */
		byte* home_dir = secure_getenv("HOME"); /* retrieve env-var HOME */
		size_t home_dir_len = strlen(home_dir);
	
		size_t data_dir_len = home_dir_len + strlen(SSCS_CONFIG_FOLDER_NAME) + 2;	
		char data_dir[data_dir_len];
	
		sprintf(data_dir,"%s/%s",home_dir,SSCS_CONFIG_FOLDER_NAME); /* concatenate home dir and the folder name */

	#else

		/* if user has defined a set path, set data_dir to said path */
		char data_dir[] = SSCS_CONFIG_ABSOLUTE_PATH;
		size_t data_dir_len = strlen(data_dir);

	#endif /* SSCS_CONFIG_SET_ABSOLUTE_PATH */
	
	char config_file[data_dir_len + 10];
	sprintf(config_file,"%ssscs_config",data_dir); /* config_file is now the full path to the config */
	loginfo("config path %s",config_file);

	SCONFIG* config = NULL; 
	if( sconfig_config_exists(config_file) == 0 ) /* config file not found */
	{
		if( mkdir(data_dir, S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST )
		{
			logerr("could not create directory (%s)- err %d, fatal",config_file,errno);
			exit(EXIT_FAILURE);
		}
		config = sconfig_load(config_file); /* load configfile */
		
		/* add log_file to config */
		char log_file[data_dir_len + 14];	
		sprintf(log_file,"%sssc_server.log",data_dir);
		sconfig_set_str(config,"SSCS_LOGFILE",log_file);
		logdbg("set SSCS_LOGFILE => %s",log_file);
		
		/* add certificate file to config */
		char cert_file[data_dir_len + 9];
		sprintf(cert_file,"%scert.pem",data_dir);
		sconfig_set_str(config,"SSCS_CERTFILE",cert_file);
		logdbg("set SSCS_CERTFILE => %s",cert_file);
	
		/* add key file to config */
		char key_file[data_dir_len + 8];
		sprintf(key_file,"%skey.pem",data_dir);
		sconfig_set_str(config,"SSCS_KEYFILE",key_file);
		logdbg("set SSCS_KEYFILE => %s",key_file);

		#ifndef RELEASE_IMAGE 	
			/* not release ready code: use debug settings */
			sconfig_set_str(config,"SSCS_KEYFILE_PW","test");
			sconfig_set_str(config,"SSCDB_SRV","127.0.0.1");
			sconfig_set_str(config,"SSCDB_USR","SSCServer");
			sconfig_set_str(config,"SSCDB_PASS","passphrase");
			sconfig_set_int(config,"SSCS_LOGTOFILE",0);
		
		#else
			/* we are in a release build, ask user for input */
		
			/* get keyfile password */
			char keyfile_pw_input[200];
			fprintf(stdout,"Please enter your SSL Private Certifiate Passphrase [200]: ");
			get_from_stdin(keyfile_pw_input,200);
			sconfig_set_str(config,"SSCS_KEYFILE_PW",keyfile_pw_input);
			logdbg("set SSCS_KEYFILE_PW => %s",keyfile_pw_input);

			/* get server ip */
			char db_srv_input[200];
			fprintf(stdout,"Please enter your MySQL/MariaDB hostname/ip [200]: ");
			get_from_stdin(db_srv_input,200);
			sconfig_set_str(config,"SSCDB_SRV",db_srv_input);
			logdbg("set SSCDB_SRV => %s",db_srv_input);

			/* get db user name */
			char db_usr_input[200];
			fprintf(stdout,"Please enter your MySQL/MariaDB username [200]: ");
			get_from_stdin(db_usr_input,200);
			sconfig_set_str(config,"SSCDB_USR",db_usr_input);
			logdbg("set SSCDB_USR => %s",db_usr_input);
		
			/* get db user password */
			char db_pass_input[200];
			fprintf(stdout,"Please enter your MySQL/MariaDB passphrase [200]: ");
			get_from_stdin(db_pass_input,200);
			sconfig_set_str(config,"SSCDB_PASS",db_pass_input);
			logdbg("set SSCDB_PASS => %s",db_pass_input);

			sconfig_set_int(config,"SSCS_LOGTOFILE",1); /* make sscs log to logfile */
		#endif
		sconfig_write(config);
	}
	else	
	{
		config = sconfig_load(config_file);
	}
	return config;
}
