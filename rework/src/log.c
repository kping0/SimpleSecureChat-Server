
#include "log.h"

static FILE* log_out_fd = NULL;
static FILE* log_err_fd = NULL;
static int log_fd_set = 0;

void log_set_fd(FILE* out_log, FILE* err_log) /* set log file out & err fd */
{
	log_out_fd = out_log;
	log_err_fd = err_log;
	log_fd_set = 1;
	return;	
}

void log_global(const char* calling_file, int calling_line, const char* calling_function, char* prefix, bool is_err, char* format_str, ...){

	if(format_str == NULL) return; /* if no string is specified then return */

	if(log_fd_set == 0) log_set_fd(stdout,stderr);	 /* if file descriptor not set use stdout and stderr */

	/* get current time */
	time_t time_obj;
	time(&time_obj);
	struct tm* time_info = localtime(&time_obj);	
	EXISTS(time_info);

	/* figure out if to write to the error fd or the out fd */
	FILE* temp_fd = log_out_fd;
	if(is_err == true)temp_fd = log_err_fd;
		
	fprintf(temp_fd,"%s(%d:%d:%d_%d:%d:%d)(%s:%i)>%s() ",prefix,time_info->tm_hour,time_info->tm_min,time_info->tm_sec,time_info->tm_mday,time_info->tm_mon+1,time_info->tm_year+1900,calling_file,calling_line,calling_function); /* print prefix */

	/* print user input */
	va_list format_str_args;
	va_start(format_str_args,format_str);
	vfprintf(temp_fd,format_str,format_str_args);	
	va_end(format_str_args);

	fprintf(temp_fd,"\n"); /* add newline */
	
	return;
}
