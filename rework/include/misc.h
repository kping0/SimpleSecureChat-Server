#ifndef MISC_H
#define MISC_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "entry.h" /* most includes headers */
#include "settings.h"

extern int listening_socket;

int ssc_signal_handler(int sig);

void do_exit();

void string_remove_newline(byte* str);

void child_exit_handler(int sig);

int nsleep(long n);

#endif /* MISC_H */
