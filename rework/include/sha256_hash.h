
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


#ifndef SSCSHASHING_HF
#define SSCSHASHING_HF

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "log.h"
#include "base64.h"
#include "settings.h"

#define SSCS_HASH_VALID 1
#define SSCS_HASH_INVALID 2

typedef unsigned char byte;

struct SSCS_HASH_STRUCT{
	byte* hash;
	size_t hash_len;
	byte* salt;
	size_t salt_len;
};
typedef struct SSCS_HASH_STRUCT SSCS_HASH;

byte* memncat(byte* first,size_t first_len,byte* second,size_t second_len); //concatenate memory blocks

SSCS_HASH* SSCS_createhash(byte* data,size_t data_len); //get b64_sha256 for data (with salt)

int SSCS_comparehash(byte* data,size_t data_len,SSCS_HASH* original_hash); //compare sha256(data) to orig

void SSCS_freehash(SSCS_HASH** hash); /* free hash struct */

#endif /* SSCSHASHING_HF */
