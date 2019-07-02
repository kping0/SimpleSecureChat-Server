#ifndef SSC_LOGGING_FUNCTIONS_H
#define SSC_LOGGING_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include "settings.h"
#include "errchk.h"


#ifndef DEBUG
	#define logdbg(x, ...)	do {} while(0)
#else
	#define logdbg(x, ...) log_global(__FILE__,__LINE__,__FUNCTION__,"[DEBUG]",false,x,##__VA_ARGS__)
#endif

#define loginfo(x, ...) log_global(__FILE__,__LINE__,__FUNCTION__,"[INFO]",false,x,##__VA_ARGS__)

#define logerr(x, ...) log_global(__FILE__,__LINE__,__FUNCTION__,"[ERROR]",true,x,##__VA_ARGS__)


void log_set_fd(FILE* out_log, FILE* err_log);

void log_global(const char* calling_file, int calling_line, const char* calling_function, char* prefix, bool is_err, char* format_str, ...);

#endif
