#ifndef SSC_CHECK_MACROS_H
#define SSC_CHECK_MACROS_H

#include <assert.h>

#define CHKFAIL(x) if(x!=0)goto FAILURE /* macro for error checking and readability */
#define EXISTS(x) assert(x != NULL) /* macro for error checking and readability */
#define SSLCHKFAIL(x) if(x!=1)goto FAILURE


#endif
