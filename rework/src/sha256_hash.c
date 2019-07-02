
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

#include "sha256_hash.h"

byte* memncat(byte* first,size_t first_len,byte* second,size_t second_len)
{
	byte* final_buffer = custom_malloc(first_len+second_len); /* allocate memory for returned buffer */
	byte* write_pointer = final_buffer;
	memcpy(write_pointer,first,first_len); /* copy first buffer to block */
	write_pointer+=first_len;
	memcpy(write_pointer,second,second_len); /* copy second buffer to block */
	return final_buffer; /* return allocated buffer */
}

SSCS_HASH* SSCS_createhash(byte* data,size_t data_len) /* create hash obj from data + data_len */
{
	byte salt[20]; 
	byte hash[SHA512_DIGEST_LENGTH];

	RAND_poll(); /* poll for randomness */
	if(!RAND_bytes(salt,20))return NULL; 
	size_t base64_salt_len = 0;
	byte* base64_salt = ssc_base64_encode(salt,20,&base64_salt_len); /* base64 encode the salt */

	byte* salt_and_data = memncat(base64_salt,base64_salt_len,data,data_len); /* concatenate base64 encoded salt and passed data */
	memset(hash,0,SHA512_DIGEST_LENGTH);
	SHA512(salt_and_data,(base64_salt_len+data_len),hash); /* get hash for salt_and_data */

	size_t base64_hash_len = 0;
	byte* base64_hash = ssc_base64_encode(hash,SHA512_DIGEST_LENGTH,&base64_hash_len); /* base64 encode the hash */

	/* create structure to return */
	SSCS_HASH* hash_struct = custom_malloc(sizeof(SSCS_HASH)); 
	hash_struct->hash = base64_hash;
	hash_struct->hash_len = base64_hash_len;
	hash_struct->salt = base64_salt;
	hash_struct->salt_len = base64_salt_len;

	/* cleanup */
	custom_free(salt_and_data);
	return hash_struct;
}

int SSCS_comparehash(byte* data,size_t data_len,SSCS_HASH* original_hash) /* compare a previous and an unknown hash */
{
	/* retrieve original hash values */
	byte* salt = original_hash->salt;
	size_t salt_len = original_hash->salt_len;
	byte* hash = original_hash->hash;
	size_t hash_len = original_hash->hash_len;
	
	/* take salt + new data and generate new hash */
	byte* salt_and_data = memncat(salt,salt_len,data,data_len);
	byte data_hash[SHA512_DIGEST_LENGTH];		
	memset(data_hash,0,SHA512_DIGEST_LENGTH);
	SHA512(salt_and_data,(salt_len+data_len),data_hash);

	/* encode new hash with base64 */
	size_t base64_data_hash_len = 0;
	byte* base64_data_hash = ssc_base64_encode(data_hash,SHA512_DIGEST_LENGTH,&base64_data_hash_len);
	if(base64_data_hash_len != hash_len){ /* check to see if they are the same length */
		custom_free(salt_and_data);
		custom_free(base64_data_hash);
		return SSCS_HASH_INVALID;
	}
	
	/* compare original and new hash */
	int result = memcmp(hash,base64_data_hash,SHA512_DIGEST_LENGTH);

	/* cleanup */
	custom_free(salt_and_data);
	custom_free(base64_data_hash);
	if(result==0)return SSCS_HASH_VALID;
	return SSCS_HASH_INVALID;
}

void SSCS_freehash(SSCS_HASH** hash) /* free hash struct */
{
	custom_free(((*hash)->hash));
	custom_free(((*hash)->salt));
	custom_free((*hash));
	*hash = NULL; /* set to NULL */
	return;
}

