
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

#ifndef SSC_SERVER_SETTINGS_H
#define SSC_SERVER_SETTINGS_H

/*
 * -- DESCRIPTION --
 * Settings for SSCServer (compile settings, cannot be changed on the fly by modifying the configfile)
 * uncomment / comment out to suit your needs
 * -- DESCRIPTION -- 
 */


/* ------ DO NOT EDIT ABOVE THIS LINE ------ */
/* ------ DO NOT EDIT ABOVE THIS LINE ------ */
/* ------ DO NOT EDIT ABOVE THIS LINE ------ */


/* should only be defined in release ready code (&must be defined if compiling for a live enviroment) (cannot be defined with DEBUG) */
	// #define RELEASE_IMAGE 

/* Print alot of debug information (cannot be defined on a release) */
	// #define DEBUG

/* Print every function call to STDOUT. Needs DEBUG. ***ALOT*** of output */
	// #define SSCS_FUNCTION_LOG

/* Print live information (encrypted message b64, salts, &etc) Needs DEBUG. ***ALOT of output */
	// #define SSCS_OUTPUT_LIVE

/* fork for every client (comment out to use threads) */
	 #define SSCS_CLIENT_FORK

/* use protected heap allocation functions */
	 #define SSCS_CUSTOM_MALLOC

/* name of config folder in $HOME */
	#define SSCS_CONFIG_FOLDER_NAME ".sscs_conf/"

/* set if you want to define an absolute path other than the default in $HOME */
	//#define SSCS_CONFIG_SET_ABSOLUTE_PATH

/* absolute path to config folder (only if using SSCS_CONFIG_ABSOLUTE_CUSTOM_PATH) */
	// #define SSCS_CONFIG_ABSOLUTE_PATH "/full/path/to/configdir/"
/* log ip addresses (toggle) */
	  #define SSCS_LOG_IP_ADDRESSES


/* ------ DO NOT EDIT BEYOND THIS LINE ------ */
/* ------ DO NOT EDIT BEYOND THIS LINE ------ */
/* ------ DO NOT EDIT BEYOND THIS LINE ------ */


#ifdef SSCS_CUSTOM_MALLOC
	#include "protected_malloc.h"
#else
	#define cmalloc(size) calloc(1,size) 
	#define cfree(ptr) free(ptr) 
	#define cmalloc_init() cempty_function()
#endif

#if defined(DEBUG) && defined(SSCS_FUNCTION_LOG)
	#define debuginfo() cfunction_info()
#else
	#define debuginfo() cempty_function()
#endif /* DEBUG && SSCS_FUNCTION_LOG */

#if defined(DEBUG) && defined(RELEASE_IMAGE) 
	#error You cannot have debug enabled in a release build. 
#endif /* DEBUG && RELEASE_IMAGE */

#if !defined(DEBUG) && defined(SSCS_OUTPUT_LIVE)
	#error You need debug enabled for live output
#endif

#endif /* SSC_SERVER_SETTINGS_H */
