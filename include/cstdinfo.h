
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

/*
 * custom info and error reporting functions
 */
#ifndef SSCS_CUSTOM_ERROR_CHK_HFILE
#define SSCS_CUSTOM_ERROR_CHK_HFILE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "settings.h"

#define cdebug(x, ...) cdebug_internal(__FUNCTION__, x, ##__VA_ARGS__)
#define cinfo(x, ...) cinfo_internal(__FUNCTION__, x, ##__VA_ARGS__)
#define cerror(x, ...) cerror_internal(__FUNCTION__, x, ##__VA_ARGS__)
#define cexit(x, ...) cexit_internal(__FUNCTION__, x, ##__VA_ARGS__)
#define ccrit(x, ...) ccrit_internal(__FUNCTION__, x, ##__VA_ARGS__)

void cinitfd(FILE* stdout_file,FILE* stderr_file); /* set the info(stdout) logfile and the error(stderr) logfile */

void cerror_internal(const char* calling_function,char* format, ...); /* print error, then return */

void cinfo_internal(const char* calling_function,char* format, ...); /* print info, then return */

void cexit_internal(const char* calling_function,char* format, ...); /* print error, then exit */

void cdebug_internal(const char* calling_function,char* format, ...); /* print debug info if DEBUG is defined, then return */

void ccrit_internal(const char* calling_function,char* format, ...); /* print critical error, then exit */

#endif /* SSCS_CUSTOM_ERROR_CHK_HFILE */