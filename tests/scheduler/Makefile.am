include $(top_srcdir)/config.mk

RTE_SDK=$(top_srcdir)/libs/dpdk
RTE_ARCH=x86_64-native-linuxapp-gcc
RTE_TARGET=build
RTE_OUTPUT=$(top_srcdir)/tests/scheduler

APP=scheduler-test

include $(RTE_SDK)/mk/rte.vars.mk

include $(RTE_SDK)/mk/rte.cpuflags.mk

bin_PROGRAMS = scheduler-test

scheduler_test_SOURCES = scheduler-test.c

scheduler_test_CFLAGS = -m64 -pthread -march=native $(AM_CFLAGS)

scheduler_test_LDFLAGS = -m64 -pthread -march=native $(MACHINE_CFLAGS) $(AM_LDFLAGS)

scheduler_test_LDADD = $(top_srcdir)/src/libflowos.la
