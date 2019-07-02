#ifndef SSC_TLS_FUNCTIONS
#define SSC_TLS_FUNCTIONS

/* c lib */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

/* OpenSSL */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

/* custom */
#include "settings.h"
#include "sconfig.h"


int ssc_init_openssl();

void ssc_cleanup_openssl();

SSL_CTX* ssl_create_context();

int ssl_configure_context(SSL_CTX* ctx);

#endif
