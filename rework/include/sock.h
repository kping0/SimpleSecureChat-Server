#ifndef SSCS_SOCK_H
#define SSCS_SOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "log.h"


int ip_listen_port(int port);

#endif /* SSCS_SOCK_H */
