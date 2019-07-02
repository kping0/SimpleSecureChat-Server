#ifndef   BASE64_H
#define   BASE64_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "settings.h"

byte* ssc_base64_encode(byte* src, size_t len, size_t *out_len);

byte* ssc_base64_decode(byte* src, size_t len, size_t *out_len);

#endif /* BASE64_H */
