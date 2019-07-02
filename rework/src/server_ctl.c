
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
#include <unistd.h>

void usage(char* argv[]){
	fprintf(stdout,"Usage: \n %s start\n %s stop\n %s log\n",argv[0],argv[0],argv[0]);
	exit(EXIT_FAILURE);
}
void bash_system(char* command){
	FILE* tfd =  popen("bash","w");
	fprintf(tfd,"%s",command);
	pclose(tfd);
	return;	
}
int main(int argc,char* argv[]){
	if(argc != 2)usage(argv);
	char* arg = argv[1];
	if(strcmp(arg,"START") == 0 || strcmp(arg,"start") == 0){
		bash_system("ssc_server & disown");
	}
	else if(strcmp(arg,"STOP") == 0 || strcmp(arg,"stop") == 0){
		bash_system("pkill ssc_server");
	}		
	else if(strcmp(arg,"LOG") == 0 || strcmp(arg,"log") == 0){
		system("watch -n 0.5 tail -n 50 ~/.sscs_conf/ssc_server.log");
	}
	else{
		usage(argv);
	}
	return 0;
}

