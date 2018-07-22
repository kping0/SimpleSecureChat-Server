
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

#ifndef _HANDLER_H
#define _HANDLER_H

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
#include "protected_malloc.h" //heap allocation functions
#include "base64.h" //MIT base64 function (BSD LICENSE)
#include "serialization.h" //SSCS Library
#include "hashing.h" // hashing implimentation (SHA256(salt+data))
#include "cstdinfo.h" //custom error & info printing
#include "simpleconfig.h" //configfile support

struct sscs_handler_data{
	int client_socket;
	SSL_CTX* ctx;
	pthread_t* thread_info;	
};

void* _ClientHandler(void* data);

#endif /* _HANDLER_H */
