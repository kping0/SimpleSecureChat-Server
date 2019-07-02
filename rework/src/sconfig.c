#include "sconfig.h"

SCONFIG* priv_sconfig_new(const char* file, int line)
{
	SCONFIG* new_config = custom_malloc(sizeof(SCONFIG)); /* allocate memory for object */
	if(!new_config)
	{
		logerr("could not allocate memory (%s:%d)",file,line);
		return NULL;
	} 	

	new_config->configpath = NULL;
	new_config->configtemp = NULL;
	new_config->lock = 0;
	
	return new_config;
}

void priv_sconfig_close(SCONFIG** config)
{
	/* check if obj exists */
	if(!config)return;
	SCONFIG* obj = *config;
	if(!obj)return;

	/* free structures */
	if(obj->configpath)custom_free(obj->configpath);
	if(obj->configtemp)SSCS_release(&(obj->configtemp));
	custom_free(obj);

	config = NULL;
	return;
}

int priv_sconfig_check(SCONFIG* obj,const char* file, int line)
{
	if(!obj)
	{
		logdbg("obj passed is NULL (%s:%d)",file,line);
		return -1;
	}
	if(!obj->configpath)
	{
		logdbg("obj->configpath is NULL (%s:%d)",file,line);
		return -2;
	}
	if(!obj->configtemp)
	{
		logdbg("obj->configtemp is NULl (%s:%d)",file,line);
		return -3;
	}
	return 0;
		
}

int sconfig_config_exists(byte* path)
{
	
	/* 
	 * Basically check if file exists by trying to open it 
	 */

	if(!path)return -1;

	FILE* tfd = fopen(path,"rb");

	if(!tfd)return 0;	
	fclose(tfd);

	return 1;
}

SCONFIG* priv_sconfig_load(byte* path, const char* file, int line) /* load configfile at path & if not found create new configfile at path */
{
	if(!path || !file || !line)return NULL;	

	SCONFIG* config = priv_sconfig_new(file,line);
	size_t path_len = strlen(path) + 1; /* get length of path */
	byte* path_heap = custom_malloc(path_len); /* allocate space on heap for copy of path */
		
	if(!path_heap) /* error checking */
	{
		/* failed to allocate memory on heap */
		logerr("failed to allocate memory (%s:%d)",file,line);
		custom_free(config); /* cleanup */
		return NULL;
	}	
	
	memcpy(path_heap,path,path_len); /* copy path to heap */
	config->configpath = path_heap; /* set obj configpath to allocated heap obj */

	FILE* config_file = fopen(path_heap,"rb");	
	if(!config_file)	/* check if file exists */
	{
		logdbg("failed to open the path specified (%s), trying to create new file..",path_heap);
		config_file = fopen(path_heap,"wb+"); /* try to open file with write enabled to create file */
		if(!config_file) /* check for success */
		{
			logerr("could not create file at (%s), fatal (%s:%d)",path_heap,file,line);
			priv_sconfig_close(&config);	
			return NULL;
		}
	}
		
	/* retrieve length of entire file */
	fseek(config_file,0,SEEK_END);
	size_t config_file_len = ftell(config_file); /* get length of entire config */
	fseek(config_file,0,SEEK_SET);

	byte* config_temp = custom_malloc(config_file_len + 1);
	if(config_temp)
	{
		fread(config_temp,1,config_file_len,config_file); /* read file contents onto heap */
		config->configtemp = SSCS_open(config_temp); /* open heap object as serialized obj */

		/* cleanup */
		custom_free(config_temp); 
		fclose(config_file);
		
		return config;
	}
	else
	{
		/* cleanup */
		logerr("failed to allocate memory (%s:%d)",file,line);
	
		custom_free(config);
		fclose(config_file);
		custom_free(path_heap);
		
		return NULL;
	}
}

void* priv_sconfig_get(SCONFIG* config, byte* label, const char* file, int line)
{
	/* make sure we can read from the configfile */
	if(!config || !label || !file || !line) return NULL;	
	if( priv_sconfig_check(config,file,line) != 0 ) return NULL;

	/* read data */
	sscsd* data = SSCS_object_data(config->configtemp,label);
	if(!data) return NULL;
	
	/* cleanup */
	byte* retptr = data->data;
	custom_free(data);	

	return retptr;
}

sscsd* priv_sconfig_get_full(SCONFIG* config, byte* label, const char* file, int line)
{
	/* make sure we can read from the configfile */
	if( !config || !label || !file || !line ) return NULL;
	if( priv_sconfig_check(config, file, line)  != 0 ) return NULL;

	/* read and return data */
	return SSCS_object_data(config->configtemp, label);
}

int priv_sconfig_get_int(SCONFIG* config, byte* label, const char* file, int line)
{
	sscsd* data = priv_sconfig_get_full(config, label, file, line); /* retrieve data */
	if( !data )
	{
		logerr("WARNING: could not retrieve int from config.. for label (%s).",label);
		return -1;
	}

	if( data->len != sizeof(int) ) /* check if data is of length int */
	{
		logerr("WARNING: size of data stored for label (%s) is not sizeof(int).",label);
		SSCS_data_release(&data);
		return -1;
	}

	/* return int and cleanup */
	int return_integer = *(int*)(data->data);
	SSCS_data_release(&data);	
	return return_integer;
}

byte* priv_sconfig_get_str(SCONFIG* config, byte* label, const char* file, int line)
{
	/* pre-checks */
	if(!config || !label || !file || !line || priv_sconfig_check(config, file, line) ){
		logerr("one req. was not met.");
		return NULL;
	}

	return SSCS_object_string(config->configtemp, label);
}

int priv_sconfig_set(SCONFIG* config, byte* label,byte* data, size_t data_len, const char* file, int line)
{
	if( !config || !label || !data || !data_len || !file || !line ) return -1;

	while(config->lock == 1)		
	{
	 	nsleep(50); /* while some other thread is writing, do sleep 50ms */
	}

	config->lock = 1; /* lock config*/

	if( priv_sconfig_check(config, file, line) )
	{
		config->lock = 0;
		return -1;
	} 	

	int ret = SSCS_object_add_data(config->configtemp, label, data, data_len);

	config->lock = 0; /* unlock config */

	return ret;
}

int priv_sconfig_set_int(SCONFIG* config, byte* label, int data_int, const char* file, int line)
{
	if(!config || !label || !data_int || !file || !line) return NULL;

	return priv_sconfig_set(config, label, &data_int, sizeof(int), file, line);
}

int priv_sconfig_unset(SCONFIG* config, byte* label, const char* file, int line)
{
	if( priv_sconfig_check(config,file,line) != 0 )	return -1;

	while(config->lock == 1)
	{
		nsleep(50); /* while config is locked, sleep 50ms */
	}

	config->lock = 1; /* lock config */
	int ret_val = SSCS_object_remove_data(config->configtemp, label);
	config->lock = 0; /* unlock config */

	return ret_val;
}

int priv_sconfig_write(SCONFIG* config, const char* file, int line)
{
	if( priv_sconfig_check(config, file, line) != 0 ) return -1;
	
	while(config->lock == 1)
	{
		nsleep(50);	
	}

	config->lock = 1;
		
	FILE* config_fd = fopen(config->configpath,"wb");
	if(!config_fd)	
	{
		logerr("failed to open path to write (%s) ",config->configpath);
		config->lock = 0;
		return -1;
	}
	
	byte* config_w_str = SSCS_object_encoded(config->configtemp); /* get encoded string for config */
	if(!config_w_str)
	{
		/* cleanup */
		logerr("failed to encode config");
		fclose(config_fd);
		config->lock = 0;
		return -1;
	}

	fprintf(config_fd,"%s",config_w_str); /* write config */
	fflush(config_fd); /* flush out buffers */
	fclose(config_fd); /* close fd */
	custom_free(config_w_str);

	config->lock = 0;

	return 0;
}

