
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


#include "loadconfig.h"

/* loadconfig(): return a ptr to a sconfig object & if config is not found, create & populate with default settings */
SCONFIG* loadconfig(void){
	char* home_dir = secure_getenv("HOME");
	size_t home_dir_l = strlen(home_dir);
	size_t data_dir_l = home_dir_l + 17;
	char data_dir[data_dir_l];
	sprintf(data_dir,"%s/.sscs_conf/",home_dir);
	char config_file[data_dir_l + 10];
	sprintf(config_file,"%ssscs_config",data_dir);
	
	SCONFIG* config = NULL;	
	if(sconfig_config_exists(config_file) == 0){
		if(mkdir(data_dir, S_IRUSR | S_IWUSR | S_IXUSR) && errno != EEXIST)cexit("Could not create ~/.ssc_local/ (errno == %d)\n",errno);
		config = sconfig_load(config_file);

		/* log file config */
		char log_file[home_dir_l + 17 + 14];
		sprintf(log_file,"%ssscs_server.log",data_dir);
		sconfig_set_str(config,"SSCS_LOGFILE",log_file);
		
		char cert_file[data_dir_l + 9];
		sprintf(cert_file,"%scert.pem",data_dir);
		char key_file[data_dir_l + 8];
		sprintf(key_file,"%skey.pem",data_dir);

		/* The SSL Certificate & Key should always be located at '~/.sscs_conf/' - 'cert/key.pem' */
		sconfig_set_str(config,"SSCS_CERTFILE",cert_file);
		sconfig_set_str(config,"SSCS_KEYFILE",key_file);

	#ifndef RELEASE_IMAGE
		/* if we are NOT in a release build */

		sconfig_set_str(config,"SSCS_KEYFILE_PW","test");
		sconfig_set_str(config,"SSCDB_SRV","localhost");
		sconfig_set_str(config,"SSCDB_USR","SSCServer");
		sconfig_set_str(config,"SSCDB_PASS","passphrase");
		sconfig_set_int(config,"SSCS_LOGTOFILE",0);		

	#else
		/*  we ARE in a release build */

		/* TODO get usr input */
		sconfig_set_int(config,"SSCS_LOGTOFILE",1);
	#endif

		sconfig_write(config);
	}
	else{
		config = sconfig_load(config_file);
	}
	if(!config)return NULL;
	return config;
}
