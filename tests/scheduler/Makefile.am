include $(top_srcdir)/config.mk

RTE_SDK=$(top_srcdir)/libs/dpdk
RTE_ARCH=x86_64-native-linuxapp-gcc
RTE_TARGET=build
RTE_OUTPUT=$(top_srcdir)/tests/scheduler

APP=scheduler

include $(RTE_SDK)/mk/rte.vars.mk

include $(RTE_SDK)/mk/rte.cpuflags.mk

bin_PROGRAMS = scheduler

scheduler_SOURCES = scheduler.c

scheduler_CFLAGS = -m64 -pthread -march=native $(AM_CFLAGS)

scheduler_LDFLAGS = -m64 -pthread -march=native $(MACHINE_CFLAGS) $(AM_LDFLAGS)

scheduler_LDADD = $(top_srcdir)/src/libflowos.la
