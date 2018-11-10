#include <errno.h>
#include <stdlib.h> 
#include <stdio.h> 
#include <assert.h>
#include <string.h> 

#include "base64.h" 
#include "serial.h"

/*
 * SimpleSecureChat Serialization Library. Made with Security in mind.
*/
byte* memseq(byte* buf,size_t buf_size,byte* byteseq,size_t byteseq_len)
{ 
	/* init variables */
	size_t i = 0;
	size_t x = 0;
	byte* firstbyte = NULL; 

	while( i < buf_size )
	{
		if( buf[i] == byteseq[x] )
		{
			firstbyte = (buf+i); /* ptr to be returned if we find the byte sequence */
			x++; /* increase the sequence index */
			i++; /* increase the index */

			while(1)
			{	
				if( x == byteseq_len )
				{
					return firstbyte; /* we have found the bytesequence */
				}
				else if( !(i < buf_size) )
				{
					return NULL; /* we have reached the buffer size, and not found the sequence */
				}
				else if( buf[i] == byteseq[x] )
				{
					/* bytes match, increase both indexes */
					x++; 
					i++;
				}
				else
				{
					/* none of the above are true, sequence does not match */
					x = 0;
					firstbyte = NULL;
					break;
				}
			}		
		}	
		else
		{
			/* do not match, increase ithe index */
			i++;
		}
	}	
	return NULL;
}

sscso *SSCS_object(void) /* allocate a SSCS object and return the address */
{ 
	sscso* obj = custom_malloc(sizeof(sscso));		
	obj->buf_ptr = NULL; 
	obj->allocated = 0;
	return obj;
}

sscsl *SSCS_list(void) /* allocate a SSCS list and return the address */
{
	sscsl* list = custom_malloc(sizeof(sscsl));
	list->buf_ptr = NULL;
	list->allocated = 0;
	list->items = 0;
	return list;
}

sscsl *SSCS_list_open(byte* buf) /* allocate a SSCS list and fill it with buffer buf */
{
	/* copy buffer */
	size_t len = strlen((const char*)buf);
	byte* buf_cpy = custom_malloc(len);
	memcpy(buf_cpy,buf,len);

	sscsl *list = custom_malloc(sizeof(sscsl));
	list->buf_ptr = buf_cpy;
	list->allocated = len;
	/* ERROR you cannot write to this list,because the items are not filled out !! */
	/* list->items = items */

	return list;
}

sscso *SSCS_open(byte* buf) /* allocate a SSCS object and fill it with buffer buf */
{
	/* copy buffer */
	size_t len = strlen((const char*)buf);
	void* buf_ptr = custom_malloc(len);
	memcpy(buf_ptr,buf,len);

	sscso* obj = custom_malloc(sizeof(sscso));
	obj->buf_ptr = buf_ptr;
	obj->allocated = len;
	return obj;
}

int SSCS_list_add_data(sscsl* list,byte* data,size_t size)
{
	if(size <= 0)return -1; /* buffer cannot be of size ZERO or smaller */ 

	/* get pointers to important objects from struct list */
	byte* old_buf_ptr = list->buf_ptr;
	size_t old_buf_size = list->allocated;	
	size_t old_buf_items = list->items;

	if(old_buf_items >= 100000)return -1; /* if more than 100k items exist in the list, exit */

	/* encode data in base64 */
	size_t encoded_size = 0;
	byte* base64_data = ssc_base64_encode(data,size,&encoded_size);
	int base64_data_len = encoded_size;

	/* create label to search for */ 
	byte label[12]; 
	sprintf(label,"%zd:\"",old_buf_items+1); /* turn number into string to search for */
	size_t label_len = strlen((const char*)label);

	/* create new buffer */
	size_t temp_buf_len = old_buf_size + label_len + base64_data_len + 2; /* old_buf";label:"base64_data"; */
	byte* temp_buf = custom_malloc(temp_buf_len);
	memset(temp_buf,0,temp_buf_len);

	byte* next_write_loc = temp_buf; /* next_write_loc is a pointer to the next area to write to */

	if(old_buf_ptr != NULL)
	{
		/* copy over the old buffer */
		memcpy(next_write_loc,old_buf_ptr,old_buf_size);
		next_write_loc += old_buf_size;

		/* cleanup */
		custom_free(old_buf_ptr);
	}
	
	/* add label */
	memcpy(next_write_loc,label,label_len);
	next_write_loc += label_len;

	/* add base64 encoded data */
	memcpy(next_write_loc,base64_data,encoded_size); 
	next_write_loc += base64_data_len;
	custom_free(base64_data);	

	/* add terminating characters */
	*(next_write_loc) = '"'; next_write_loc++; 
	*next_write_loc = ';';	next_write_loc++;

	/* return object */
	list->allocated = temp_buf_len;
	list->buf_ptr = temp_buf;
	list->items = old_buf_items+1;
	return 0;
}

int SSCS_object_add_data(sscso* obj,byte* label,byte* data,size_t size)
{
	/* Size cannot be ZERO or smaller */
	if( size <= 0 )return -1;
	
	/* get pointers to important objects in memory */
	byte* old_buf_ptr = obj->buf_ptr;
	size_t old_buf_size = obj->allocated;	
	
	/* create modified label object */
	size_t label_len = strlen((const char*)label);
	size_t mod_label_len = label_len + 2;

	byte mod_label[mod_label_len];
	memcpy(mod_label,label,label_len);
	mod_label[label_len] = ':';
	mod_label[label_len+1] = '"';

	if( old_buf_ptr != NULL )
	{
		/* we need to check if the label is in use already */
		byte* validation_pointer = memseq(old_buf_ptr,old_buf_size,mod_label,mod_label_len); 
		if( validation_pointer != NULL )
		{
			/* label is in use */
			loginfo("Could not add data, label already exists (%s)",label);
			return -1;
		}
	}

	/* encode data in base64 */
	size_t encoded_size = 0;
	byte* base64_data = ssc_base64_encode(data,size,&encoded_size);
	int base64_data_len = encoded_size;

	/* create new buffer */
	size_t temp_buf_len = old_buf_size + mod_label_len + base64_data_len + 2; /* old_buf";label:"base64_data"; */
	byte* temp_buf = custom_malloc(temp_buf_len);
	memset(temp_buf,0,temp_buf_len);

	byte* next_write_loc = temp_buf; /* next_write_loc is a pointer to the next area to write to */

	if( old_buf_ptr != NULL )
	{
		/* copy over the old buffer */
		memcpy(next_write_loc,old_buf_ptr,old_buf_size);
		next_write_loc += old_buf_size;

		/* cleanup */
		custom_free(old_buf_ptr);
	}
	
	/* add label */
	memcpy(next_write_loc,mod_label,mod_label_len); /* -1 for NULL TERM */
	next_write_loc += mod_label_len;

	/* add base64 encoded data */
	memcpy(next_write_loc,base64_data,encoded_size); 
	next_write_loc += base64_data_len;
	custom_free(base64_data);	

	/* add terminating characters */
	*(next_write_loc) = '"'; next_write_loc++; 
	*next_write_loc = ';';	next_write_loc++;

	obj->allocated = temp_buf_len;
	obj->buf_ptr = temp_buf;
	return 0;
}

int SSCS_object_remove_data(sscso* obj,byte* label)
{
	if(!label)return -1;

	/* retrieve important variables */
	size_t buf_size = obj->allocated;	
	byte *buf_ptr = obj->buf_ptr;
	
	if(buf_ptr == NULL)
	{
		return -1;
	}
	
	/* create modified label */
	size_t label_len = strlen((const char*)label);
	size_t mod_label_len = label_len+3;

	byte mod_label[mod_label_len];
	sprintf(mod_label,"%s:\"",label);


	/* check if label exists */
	byte* label_data = memseq(buf_ptr, buf_size, (byte*)mod_label, mod_label_len);
	if(label_data == NULL)
	{
		loginfo("There is no data associated with the label '%s'",label);
		return -1;
	}

	byte* write_ptr = label_data + mod_label_len; /* ptr to start of base64_data */

	/* get length of data */
	size_t count_iteration = 0;
	while(write_ptr[count_iteration] != '"' && write_ptr[count_iteration+1] != ';'){
		if( !( ( write_ptr + count_iteration ) - buf_ptr < (signed)buf_size ) )
		{
			logerr("out of bounds loop");
			return -1;	
		}
		count_iteration++;	
	}
	count_iteration+=2; //for the ' "; ' at the end


	/* set the unused block to zero */
	memset(label_data,0x0,count_iteration+mod_label_len);		

	/* size of old data that is NOT removed */
	size_t buf_ptr_to_label_data = label_data - buf_ptr;
	logdbg("calculated buf_ptr_to_label_data %d",buf_ptr_to_label_data);

	/* calculate the size of the block after the one we removed */
	size_t after_data_to_allocated = buf_size - buf_ptr_to_label_data - count_iteration - mod_label_len; 
	byte* after_data_to_allocated_buf = buf_ptr + after_data_to_allocated;
	logdbg("calculated label_data_to_allocated %d",after_data_to_allocated);


	/* calculate new final size */
	size_t buffer_size_after_remove = buf_ptr_to_label_data + after_data_to_allocated;
	logdbg("final buffer size after remove is %d",buffer_size_after_remove);

	/* copy buffer over to new memory */
	byte* new_buf_ptr = custom_malloc(buffer_size_after_remove);
	memcpy(new_buf_ptr, buf_ptr, buf_ptr_to_label_data); /* buffer before */	
	memcpy(new_buf_ptr + buf_ptr_to_label_data, after_data_to_allocated_buf, after_data_to_allocated); /* buffer after */


	obj->buf_ptr = new_buf_ptr;
	obj->allocated = buffer_size_after_remove;

	/* cleanup */
	custom_free(buf_ptr);
	return 0;
}

sscsd* SSCS_object_data(sscso* obj,byte* label)
{
	/* get important pointers */
	byte* buf_ptr = obj->buf_ptr;
	size_t allocated = obj->allocated;

	/* create modified label */
	size_t label_len = strlen((const char*)label);
	size_t mod_label_len = label_len+2;

	byte mod_label[mod_label_len];
	memcpy(mod_label,label,label_len);
	mod_label[label_len] = ':';	
	mod_label[label_len+1] = '"';

	/* find object in memory */
	byte* read_pointer = memseq(buf_ptr,allocated,mod_label,mod_label_len);
	if( read_pointer == NULL )
	{
		return NULL;
	}

	read_pointer+=mod_label_len; /* move read_pointer to the start of the base64 encoded data */

	/* get length of string */
	int i = 0;
	while( read_pointer[i] != '"' && read_pointer[i+1] != ';' )
	{  
		if( !( (read_pointer + i - buf_ptr) < (signed)allocated ) )
		{
			logerr("outside of memory bounds read");
			return NULL;
		}

		i++; /* increase index */
	}

	/* allocate new buffer */
	size_t base64_buf_len = i + 1;
	byte* base64_buf = custom_malloc(base64_buf_len); /* allocate buffer */
	memset(base64_buf,0x0,base64_buf_len);

	/* copy over result to base64 buffer */
	memcpy(base64_buf,read_pointer,i); /* copy over our buffer */
	base64_buf[base64_buf_len] = 0x0; /* sanity null terminator */
	

	sscsd* final = custom_malloc(sizeof(sscsd)); /* allocate data object */

	/* copy decoded buffer to data object & set final->len to data length */
	final->data = ssc_base64_decode(base64_buf,base64_buf_len,&(final->len)); 

	custom_free(base64_buf);
	return final;
}

sscsd* SSCS_list_data(sscsl* list,unsigned int index)
{
	if(index > 100000)
	{
		/* do not support more than 100K items */
		return NULL;
	}
	/* retrieve important variables */
	byte* buf_ptr = list->buf_ptr;
	size_t allocated = list->allocated;

	/* cut together label */
	byte label[10]; /* max required for 100K items (ex. 100000:") */
	sprintf(label,"%d:\"",index);
	size_t label_len = strlen((const char*)label);

	/* check if item exists */
	byte* read_pointer = memseq(buf_ptr,allocated,(byte*)label,label_len);
	if(read_pointer == NULL)
	{
		return NULL;
	}

	read_pointer+=label_len; /* move readpointer to start of base64 encoded data */

	/* get length of string */
	int i = 0;
	while( read_pointer[i] != '"' && read_pointer[i+1] != ';' )
	{  
		if( !( (read_pointer + i - buf_ptr) < (signed)allocated ) )
		{
			logerr("outside of memory bounds read");
			return NULL;
		}

		i++; /* increase index */
	}

	/* allocate new buffer */
	size_t base64_buf_len = i + 1;
	byte* base64_buf = custom_malloc(base64_buf_len); /* allocate buffer */
	memset(base64_buf,0x0,base64_buf_len);

	/* copy over result to base64 buffer */
	memcpy(base64_buf,read_pointer,i); /* copy over our buffer */
	base64_buf[base64_buf_len] = 0x0; /* sanity null terminator */

	sscsd* final = custom_malloc(sizeof(sscsd)); /* allocate data object */

	/* copy decoded buffer to data object & set final->len to data length */
	final->data = ssc_base64_decode(base64_buf,base64_buf_len,&(final->len)); 

	custom_free(base64_buf);
	return final;
}

byte* SSCS_object_encoded(sscso* obj) /* return string to send over socket */
{
	/* allocate new string */
	byte* retptr = custom_malloc(obj->allocated + 1);

	/* copy over object */
	memcpy(retptr, obj->buf_ptr, obj->allocated);

	/* add null terminator */
	retptr[obj->allocated] = 0x0;

	return retptr;
}

size_t SSCS_object_encoded_size(sscso* obj) /* size of string that is sent over the socket / or just run strlen() */
{
	return obj->allocated+1;
} 
byte* SSCS_list_encoded(sscsl* list)
{
	/* allocate new string */
	byte* retptr = custom_malloc(list->allocated+1);

	/* copy over list */
	memcpy(retptr,list->buf_ptr,list->allocated);

	/* add null terminator */
	retptr[list->allocated] = 0x0;

	return retptr;
}
size_t SSCS_list_encoded_size(sscsl* list)
{
	return list->allocated+1;
}

byte* SSCS_data_get_data(sscsd* data)
{
	return data->data;
}

size_t SSCS_data_get_size(sscsd* data)
{
	return data->len;
}

void SSCS_release(sscso** obj) /* cleanup object (ex. SSCS_release(&obj); ) */
{
	if(*obj == NULL)return;

	custom_free(((*obj)->buf_ptr));
	custom_free(*obj);
	*obj = NULL;
	return;
}

void SSCS_data_release(sscsd** data) /* cleanup data object (ex. SSCS_data_release(&data); )  */
{
	if(*data == NULL)return;

	custom_free(((*data)->data));
	custom_free(*data);
	*data = NULL;	
}

void SSCS_list_release(sscsl** list)
{
	if(*list == NULL)return;

	if((*list)->buf_ptr != NULL)custom_free(((*list)->buf_ptr));
	custom_free(*list);
	*list = NULL;
}

/*
* Wrappers for SSCS_object_data() to simplify usage 
*/
int SSCS_object_int(sscso* obj,byte* label)
{
	sscsd* data = SSCS_object_data(obj,label); /* get data object */
	if(data == NULL)return -1;

	if(data->len != sizeof(int))
	{
		logerr("data is NOT an integer");
		SSCS_data_release(&data);
		return -1;
	}

	/* cast the dereferenced object to an int */
	int retval = *(int*)(data->data);
	SSCS_data_release(&data);

	return retval;
}

double SSCS_object_double(sscso* obj,byte* label)
{
	sscsd* data = SSCS_object_data(obj,label); /* get data object */
	if(data == NULL)return -1;

	if(data->len != sizeof(double))
	{
		logerr("data is NOT a double");
		SSCS_data_release(&data);
		return -1;
	}	
	/* cast teh derefenced object to a double */
	double retval = *(int*)data->data;
	SSCS_data_release(&data);

	return retval;
}

unsigned char* SSCS_object_string(sscso* obj,byte* label)
{
	sscsd* data = SSCS_object_data(obj,label); /* get data object */
	if(data == NULL)return NULL;

	/* allocate buffer for string */
	byte* ret_ptr = custom_malloc(data->len+1); 

	/* copy over data buf */
	memcpy(ret_ptr,data->data,data->len);

	/* add null terminator */
	ret_ptr[data->len] = 0x0;

	/* cleanup */
	SSCS_data_release(&data);
	
	return ret_ptr;
	
}

