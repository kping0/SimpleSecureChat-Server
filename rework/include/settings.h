#ifndef   SSC_COMPILE_SETTINGS_H
#define   SSC_COMPILE_SETTINGS_H

typedef unsigned char byte;

#define REGISTER_USER 0x01
#define AUTHENTICATE_USER 0x02
#define REQUEST_USER_PUBLIC 0x03
#define REQUEST_MESSAGES 0x04
#define SEND_MESSAGE 0x05
#define REQUEST_USER_PUBLIC_RESPONSE 0x06


/*
 * Compile time settings for SimpleSecureChat-Server. Define to activate. 
 * All child declarations only work if their parents are declared 
 * ex: SSCS_CONFIG_ABSOLUTE_PATH needs SSCS_CONFIG_SET_ABSOLUTE_PATH defined.
 */

/* start of settings */

// #define RELEASE_IMAGE /* Define if code is release ready */

 #define DEBUG  /* Define to enable debug output */
	// #define SSCS_OUTPUT_LIVE /* Print sensitive information to log (base64 of encrypted messages, salts etc */

#define SSCS_CLIENT_FORK

#define SSCS_CUSTOM_MALLOC

#define SSCS_CONFIG_FOLDER_NAME ".sscs_conf/"

// #define SSCS_CONFIG_SET_ABSOLUTE_PATH
	// #define SSCS_CONFIG_ABSOLUTE_PATH "/full/path/to/configfolder"

#define SSCS_LOG_IP_ADDRESSES


/* end of settings */

#if defined(DEBUG) && defined(RELEASE_IMAGE)
	#error Release images cannot have DEBUG enabled.
#endif 

#if !defined(DEBUG) && defined(SSCS_OUTPUT_LIVE)
	#error Live output needs debug to function
#endif

#ifndef SSCS_CUSTOM_MALLOC
	#define custom_malloc(x) calloc(1,x)
	#define custom_free(x) free(x)
#else
	#include "heap.h"
#endif


#endif /* SSC_COMPILE_SETTINGS */
