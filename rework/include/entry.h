/* Header file for src/entry.c */
#ifndef ENTRY_H
#define ENTRY_H

/* C Lib */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
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

/* Mysql */
#include <my_global.h>
#include <mysql.h>

/* Custom Headers */
#include "db.h" /* MySQL related code */
#include "settings.h" /* Compile-time Settings */
#include "heap.h" /* Protected Allocation code */
#include "base64.h" /* base64-related code */
#include "serial.h" /* serialization-related code */
#include "sha256_hash.h" /* sha256 related code */
#include "log.h" /* error / info logging related code */
#include "sconfig.h" /* simple configuration storage related code */
#include "sock.h" /* socket */
#include "session.h" /* client session related code */
#include "read_config.h" /* configuration loading code */
#include "errchk.h" /* checking macros */
#include "tls.h" /* tls functions */

#endif 
