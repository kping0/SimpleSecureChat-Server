#ifndef SSCS_DB_H
#define SSCS_DB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <my_global.h>
#include <mysql.h>

#include "serial.h"
#include "log.h"
#include "settings.h"
#include "base64.h"
#include "sha256_hash.h"
#include "sconfig.h"


int cust_mysql_query(MYSQL* con, byte* query);

void exit_mysql_err(MYSQL* con);

int ssc_init_db();

MYSQL* get_db_handle(); 

int check_user_exists(byte* username,MYSQL* db);

int add_user_to_db(byte* username, byte* base64_rsa, size_t rsa_len, byte* auth_key, MYSQL* db);

int get_user_uid(byte* username, MYSQL* db);

int store_message_to_db(MYSQL* db,byte* recipient, byte* message);

byte* get_encoded_public(byte* username, MYSQL* db);

byte* get_enc_user_messages(byte* username, MYSQL* db);

SSCS_HASH* get_user_auth_hash(byte* username, MYSQL* db);

#endif /* SSCS_DB_H */
