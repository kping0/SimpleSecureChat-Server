#ifndef READ_CONFIG_H
#define READ_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "sconfig.h"
#include "settings.h"

SCONFIG* load_config();

#endif
