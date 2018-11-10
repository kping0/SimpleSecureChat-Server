#ifndef SCONFIG_H 
#define SCONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "serial.h"

typedef struct
{
	byte* configpath;
	sscso* configtemp;
	volatile sig_atomic_t lock;
}SCONFIG;

#include "misc.h"
#include "log.h"


/* macros to simplify parameters and names */
#define sconfig_new() priv_sconfig_new(__FILE__,__LINE__)
#define sconfig_close(x) priv_sconfig_close(&x)
#define sconfig_load(x) priv_sconfig_load(x,__FILE__,__LINE__)
#define sconfig_check(x) priv_sconfig_check(x,__FILE__,__LINE__)

#define sconfig_get(x,y) priv_sconfig_get(x,y,__FILE__,__LINE__)
#define sconfig_get_full(x,y) priv_sconfig_get_full(x,y,__FILE__,__LINE__)
#define sconfig_get_int(x,y) priv_sconfig_get_int(x,y,__FILE__,__LINE__)
#define sconfig_get_str(x,y) priv_sconfig_get_str(x,y,__FILE__,__LINE__)

#define sconfig_set(x,y,a,b) priv_sconfig_set(x,y,a,b,__FILE__,__LINE__)
#define sconfig_set_int(x,y,z) priv_sconfig_set_int(x,y,z,__FILE__,__LINE__)
#define sconfig_set_str(x,y,z) priv_sconfig_set(x,y,z,strlen(z),__FILE__,__LINE__)
#define sconfig_unset(x,y) priv_sconfig_unset(x,y,__FILE__,__LINE__)

#define sconfig_write(x) priv_sconfig_write(x,__FILE__,__LINE__)


/* create and destroy SCONFIG objects */
SCONFIG* priv_sconfig_new(const char* file, int line);
void priv_sconfig_close(SCONFIG** config);

/* checking functions */
int priv_sconfig_check(SCONFIG* obj,const char* file, int line);

int sconfig_config_exists(byte* path);

/* load config from path */
SCONFIG* priv_sconfig_load(byte* path, const char* file, int line);

/* retrieve items from temp config */
void* priv_sconfig_get(SCONFIG* config, byte* label, const char* file, int line);
sscsd* priv_sconfig_get_full(SCONFIG* config, byte* label, const char* file, int line);
int priv_sconfig_get_int(SCONFIG* config, byte* label, const char* file, int line);
byte* priv_sconfig_get_str(SCONFIG* config, byte* label, const char* file, int line);

/* write to temp config */
int priv_sconfig_set(SCONFIG* config, byte* label,byte* data, size_t data_len, const char* file, int line);
int priv_sconfig_set_int(SCONFIG* config, byte* label, int data_int, const char* file, int line);
int priv_sconfig_unset(SCONFIG* config, byte* label, const char* file, int line);

/* write temp config to disk */
int priv_sconfig_write(SCONFIG* config, const char* file, int line);

#endif /* SCONFIG_H */
