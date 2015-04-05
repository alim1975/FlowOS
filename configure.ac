AC_INIT([FlowOS], [2.0], [a.alim@imperial.ac.uk])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CHECK_LIB(pthread, pthread_create, [PTHREAD_LIBS+=-lpthread])
AC_PROG_CC
AC_PROG_LD
AM_PROG_AR

LT_INIT
AC_PROG_LIBTOOL(libtool)

abs_src_dir="`cd $srcdir; pwd`"
AC_SUBST([abs_src_dir])

AC_ARG_WITH([dpdk],
	AS_HELP_STRING([--with-dpdk=PATH],
	[Path to DPDK build directory [[$(abs_src_dir)/lib/dpdk/build]]]),
	[dpdkdir="$withval"],
	[dpdkdir=$abs_src_dir/lib/dpdk/build])
AC_SUBST([dpdkdir])

AC_ARG_WITH([mtcp],
	AS_HELP_STRING([--with-mtcp=PATH],
	[Path to mTCP source directory [[$(abs_src_dir)/lib/mtcp]]]),
	[mtcpdir="$withval"],
	[mtcpdir=$abs_src_dir/lib/mtcp])
AC_SUBST([mtcpdir])

AC_CONFIG_FILES([Makefile
        src/Makefile
	tests/Makefile
	tests/scheduler/Makefile
	tests/channel/Makefile
])
AC_OUTPUT

