#include "misc.h"
/* put functions that do not belong anywhere here */

extern int listening_socket;

int ssc_signal_handler(int sig) 
{
	(void)sig; /* suppress error message */
	logdbg("Caught Signal, Closing");

	/* cleanup */
	mysql_library_end();
	ssc_cleanup_openssl();

	/* close listening socket so it can be reused quickly */
	close(listening_socket);

	exit(EXIT_SUCCESS); /* halt execution */
}

void do_exit() /* exit that chooses between exit() and pthread_exit() depending on config */
{
	#ifdef SSCS_CLIENT_FORK
		exit(EXIT_FAILURE);	
	#else
		pthread_exit(NULL);
	#endif
	return;
} /* do_exit() */

void string_remove_newline(byte* str){ /* remove a newline from a string */
	char* newline = strchr(str,'\n');
	if(newline != NULL)
	{
		*newline = 0x0;
	}
}

void child_exit_handler(int sig)
{
	(void)sig; /* suppress warning */
	int saved_errno = errno; /* save errno */

	while( waitpid( (pid_t)(-1), 0, WNOHANG ) > 0 ){} /* kill all zombies */

	errno = saved_errno;	
	return;	
}

int nsleep(long n) /* sleep for n milliseconds */
{
	struct timespec req, rem;
	if(n > 999)
	{
		req.tv_sec = n / 1000;
		req.tv_nsec = (n - (req.tv_sec * 1000)) * 1000000;
	}
	else
	{
		req.tv_sec = 0;
		req.tv_nsec = n * 1000000;
	}

	return nanosleep(&req, &rem);
}
