#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([argon2], [20190614], [https://github.com/P-H-C/phc-winner-argon2/issues])
AC_CONFIG_SRCDIR([include/argon2.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
KERNEL_NAME=`uname -s`
if test "$KERNEL_NAME" = "Linux"; then
  AC_CHECK_LIB([dl], [dlopen], [EXTRA_LIBS="-ldl"])
  AC_CHECK_LIB([rt], [shm_open], [EXTRA_LIBS="$EXTRA_LIBS -lrt"])
fi
AC_SUBST(EXTRA_LIBS)

# Checks for header files.
AC_CHECK_HEADERS([limits.h stddef.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strtoul])

AC_CONFIG_FILES([Makefile
                 libargon2.pc])
AC_OUTPUT
