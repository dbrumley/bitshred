#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.65])
AC_INIT([bitshred_openmp], [0.1], [jiyongj@cmu.edu])
AM_INIT_AUTOMAKE([bitshred_openmp], [0.1])
AC_CONFIG_SRCDIR([src/bitshred.c])
#AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lbfd':
#AC_CHECK_LIB([bfd], [bfd_init], [], [AC_MSG_ERROR(missing bfd library)])
# FIXME: Replace `main' with a function in `-ldb':
#AC_CHECK_LIB([db], [db_create], [], [AC_MSG_ERROR(missing berkeley db library)])
# FIXME: Replace `main' with a function in `-lopcodes':
#AC_CHECK_LIB([opcodes], [init_disassemble_info], [], [AC_MSG_ERROR(missing bfd library)])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdint.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset strdup strrchr])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
