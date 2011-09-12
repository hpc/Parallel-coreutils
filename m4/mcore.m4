dnl PZK >
# mcore.m4 serial 1

dnl Copyright 2010 United States Government National Aeronautics and
dnl Space Administration (NASA).  No copyright is claimed in the United
dnl States under Title 17, U.S. Code.  All Other Rights Reserved.

dnl Written by Paul Kolano.

AC_DEFUN([gl_MCORE_LIBM], [
    AC_CHECK_LIB([m], [pow])
])

AC_DEFUN([gl_MCORE_LIBRT], [
    AC_CHECK_LIB([rt], [clock_gettime])
])

AC_DEFUN([gl_MCORE_LIBGNUTLS_EXTRA], [
    AC_CHECK_LIB([gnutls-extra], [gnutls_extra_check_version], [
        LIBS="$LIBS -Wl,-Bstatic -lgnutls-extra -Wl,-Bdynamic"
        AC_DEFINE([HAVE_LIBGNUTLS_EXTRA], [1], [
            Define to 1 if you have the 'gnutls-extra' library ('lgnutls-extra')
        ])
    ])
    AC_REQUIRE([gl_MCORE_LIBGNUTLS])
])

AC_DEFUN([gl_MCORE_LIBGNUTLS], [
    AC_CHECK_HEADERS([gnutls/gnutls.h])
    AC_CHECK_LIB([gnutls], [gnutls_global_init], [
        LIBS="$LIBS -Wl,-Bstatic -lgnutls -Wl,-Bdynamic"
        AC_DEFINE([HAVE_LIBGNUTLS], [1], [
            Define to 1 if you have the 'gnutls' library ('lgnutls')
        ])
    ])
    AC_CHECK_LIB([z], [zlibVersion], [
        LIBS="$LIBS -Wl,-Bstatic -lz -Wl,-Bdynamic"
        AC_DEFINE([HAVE_LIBZ], [1], [
            Define to 1 if you have the 'z' library ('lz')
        ])
    ])
])

AC_DEFUN([gl_MCORE_LIBGCRYPT], [
    AC_CHECK_HEADERS([gcrypt.h])
    AC_CHECK_LIB([gcrypt], [gcry_md_open], [
        LIBS="$LIBS -Wl,-Bstatic -lgcrypt -Wl,-Bdynamic"
        AC_DEFINE([HAVE_LIBGCRYPT], [1], [
            Define to 1 if you have the 'gcrypt' library ('lgcrypt')
        ])
    ])
    AC_CHECK_LIB([gpg-error], [gpg_err_init], [
        LIBS="$LIBS -Wl,-Bstatic -lgpg-error -Wl,-Bdynamic"
        AC_DEFINE([HAVE_LIBGPG_ERROR], [1], [
            Define to 1 if you have the 'gpg-error' library ('lgpg-error')
        ])
    ])
])

AC_DEFUN([gl_MCORE_LIBLUSTREAPI], [
    AC_CHECK_HEADERS([lustre/liblustreapi.h])
    AC_CHECK_LIB([lustreapi], [llapi_file_get_stripe])
])

AC_DEFUN([gl_MCORE_LIBMPI], [
    AC_CHECK_HEADERS([mpi.h])
    AC_CHECK_LIB([mpi], [MPI_Init])
])

AC_DEFUN([gl_MCORE_LIBOMP], [
    LIBS="$LIBS -Wl,--no-as-needed"
    AC_OPENMP
])

dnl < PZK

