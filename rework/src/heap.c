
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

#include "heap.h"

/*
 * Check address for padding errors
 */
void sscs_chkaddr(void* ptr,const char* file,int line) /* Check passed address for any type of padding issues */
{
	void* orig = ptr-21; //get original allocated buffer
	byte* read_pointer = (byte*)orig;	

	int check_value = *(int*)read_pointer; 
	if(check_value != SSCS_HEAP_MAGIC){ /* check if check_value matches the magic number */
		logerr(" sscs_chkaddr() header checksum error - Called from %s - line %d\n",file,line);
		exit(EXIT_FAILURE);
	}
	read_pointer+=4; 

	/* read canary */
	byte* rngbytes = read_pointer;
 	read_pointer += 8;

	/* read buffer_size (size_t */
	size_t bufsize = *(size_t*)read_pointer; 
	read_pointer += 8;

	if(bufsize <= 0) 
	{
		logerr(" sscs_chkaddr() bufsize <= 0 - Called from %s - line %d\n",file,line);
		exit(EXIT_FAILURE);
	}

	if(*read_pointer != 0x0) /* missing 0x0 */
	{
		logerr(" sscs_chkaddr() incorrect padding (!0x0) - Called from %s - line %d\n",file,line);
		exit(EXIT_FAILURE);
	}	
	read_pointer++;	

	read_pointer+=bufsize; /* skip over actual buffer (not controlled by this code) */

	if(*read_pointer != 0x0) /* missing 0x0 (null ptr) */
	{
		logerr(" sscs_chkaddr() (tail) incorrect padding - Called from %s - line %d\n",file,line);
		exit(EXIT_FAILURE);
	}
	read_pointer++;

	if( memcmp(rngbytes,read_pointer,8) ) /* check canary for any mismatches */
	{
		logerr(" sscs_chkaddr() (tail) header-tail rng doesnt match - Called from %s - line %d\n",file,line);	
		exit(EXIT_FAILURE);
	}
	read_pointer+=8;

	check_value = *(int*)read_pointer;
	if(check_value != SSCS_HEAP_MAGIC) /* check if check_value matches the magic number */
	{
		logerr(" sscs_chkaddr() tail checksum error - Called from %s - line %d\n",file,line);
		exit(EXIT_FAILURE);
	}
	return;	
}

size_t sscs_heap_object_size(void* ptr,const char* file,int line)
{
	sscs_chkaddr(ptr,file,line); //check address for padding issues 
	return *((size_t*)(ptr-9)); //return sizeof usable buffer
}

byte* gen_rdm_bytestream (size_t num_bytes) /* generate semi-random bytestream */
{ 
	byte* stream = malloc(num_bytes);
	size_t i;
	for (i = 0; i < num_bytes; i++){
		stream[i] = rand ();
	}
	return stream;
}

void* sscs_cmalloc(size_t size,const char* file, int line)
{
	if(size <= 0)return NULL; /* cannot allocate a buffer smaller than or eq to 0 */
	size_t origsize = size;
/*
 * Calculate size to allocate (must be a multiple of PAGESIZE)
 */ 
	size += 40; //add 40Bytes for Padding
	size_t alloc_len = size + PAGESIZE - (size % PAGESIZE) + PAGESIZE; /* get next multiple of pagesize that fits size&metadata + guardpage length */

	char* buf = aligned_alloc(PAGESIZE,alloc_len); /* allocate aligned memory */
	if(!buf)
	{
		logerr("cmalloc() could not allocate aligned memory (called from %s line %d)\n",file,line);
		return NULL;
	}
	memset(buf,0,alloc_len); /* clear allocated buffer */

	if(mprotect(buf+(alloc_len-PAGESIZE),PAGESIZE,PROT_NONE) != 0) /* add a guardpage to the end of our buffer */
	{
		fprintf(stderr,"[ERROR] Could not add guard page (called from %s line %d): ",file,line);
		switch(errno)
		{
			case EACCES:
				fprintf(stderr,"EACCES (Memory Access Error)\n");
				free(buf);
				return NULL;
				break;
			case EINVAL:
				fprintf(stderr,"EINVAL ( (internal)buf ptr !valid OR not correctly aligned)\n");			
				free(buf);
				return NULL;
				break;
			case ENOMEM:
				fprintf(stderr,"ENOMEM (Kernel struct allocation error OR invalid address range)\n");
				free(buf);
				return NULL;
				break;
			case EFAULT:
				fprintf(stderr,"EFAULT (Memory cannot be accessed)\n");
				free(buf);
				return NULL;
				break;
			default:
				fprintf(stderr,"Unknown Error\n");
				free(buf);
				return NULL;
				break;
		}
	}
	/* add metadata */
	void* writepointer = buf;
	*(int*)writepointer = SSCS_HEAP_MAGIC; writepointer += 4; //add SSCS_HEAP_MAGIC  
	size_t* checkvar = (size_t*)gen_rdm_bytestream(8); //add secret magic
	*(size_t*)writepointer = *checkvar; writepointer += 8; // add check variable
	*(size_t*)writepointer = origsize; writepointer += 8; //add size 
	*(char*)writepointer = 0x0; writepointer++; //padding
	void* retptr = writepointer; writepointer+=origsize; //actual buffer - we dont touch it
	*(char*)writepointer = 0x0; writepointer++; //padding	
	*(size_t*)writepointer = *checkvar; writepointer += 8; //add check variable 
	*(int*)writepointer = SSCS_HEAP_MAGIC; writepointer += 4; //add SSCS_HEAP_MAGIC
	free(checkvar);	
	return retptr;
}

void sscs_cfree(void* ptr,const char* file,int line)
{
	if(ptr == NULL)
	{
		logdbg(" ptr passed is NULL\n");
		return;
	}
	void* orig = ptr-21; //go back to original metasize buffer
	sscs_chkaddr(ptr,file,line);

/*
 * We need to calculate the size of the original buffer the way we allocated it so we can reverse the 
 * guard page to avoid some nasty bugs
 */
	size_t size = sscs_heap_object_size(ptr,file,line);
	size += 40;
	size_t alloc_len = size + PAGESIZE - (size % PAGESIZE) + PAGESIZE; /* calculate buffersize */

	if(mprotect(orig+(alloc_len-PAGESIZE),PAGESIZE,PROT_READ | PROT_WRITE) != 0) /* make the page R+W again */
	{
		fprintf(stderr,"[ERROR] Could not undo guardpage (called from %s line %d): ",file,line);
		switch(errno)
		{
			case EACCES:
				fprintf(stderr,"EACCES (Memory Access Error)\n");
				return;
				break;
			case EINVAL:
				fprintf(stderr,"EINVAL ( (internal)buf ptr !valid OR not correctly aligned)\n");			
				return;
				break;
			case ENOMEM:
				fprintf(stderr,"ENOMEM (Kernel struct allocation error OR invalid address range)\n");
				return;
				break;
			case EFAULT:
				fprintf(stderr,"EFAULT (Memory cannot be accessed)\n");
				return; 
				break;
			default:
				fprintf(stderr,"Unknown Error\n");
				return;
				break;
		}
	}
	free(orig); /* free buffer */
	return;	
}
