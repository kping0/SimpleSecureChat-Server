#ifndef SSC_CLIENT_HANDLER_H
#define SSC_CLIENT_HANDLER_H

/* C lib */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* OpenSSL */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* MySQL */
#include <mysql.h>
#include <my_global.h>

/* Custom Headers */
#include "db.h" /* MySQL related code */
#include "settings.h" /* Compile-time Settings */
#include "heap.h" /* Protected Allocation code */
#include "base64.h" /* base64-related code */
#include "serial.h" /* serialization-related code */
#include "sha256_hash.h" /* sha256 related code */
#include "log.h" /* error / info logging related code */
#include "sconfig.h" /* simple configuration storage related code */
#include "session.h" /* client session related code */
#include "read_config.h" /* configuration loading code */
#include "misc.h" /* checking macros */

typedef struct
{
	SSL_CTX* ssl_ctx;
	int client_conn;	
	pthread_t* thread_info;
}HANDLER_DATA;

void string_remove_newline(byte* str); /* remove newline */

void ssc_handle_client(void* client_info_void); /* main client handler */

#endif 
