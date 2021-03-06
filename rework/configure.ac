#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([SimpleSecureChat-Server], [1.4b], [kping0@protonmail.com])
AC_CONFIG_SRCDIR([src/entry.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([subdir-objects 1.11 -Wall -Werror])
AC_CONFIG_FILES([makefile])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([crypto], [ERR_load_crypto_strings])
AC_CHECK_LIB([crypto],[ERR_print_errors_fp])
AC_CHECK_LIB([pthread], [pthread_exit])
AC_CHECK_LIB([ssl], [SSL_load_error_strings])
AC_CHECK_LIB([ssl], [SSL_clear])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memmove memset mkdir socket strchr strerror])

AC_OUTPUT
