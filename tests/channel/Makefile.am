include $(top_srcdir)/config.mk

RTE_SDK=$(top_srcdir)/libs/dpdk
RTE_ARCH=x86_64-native-linuxapp-gcc
RTE_TARGET=build
RTE_OUTPUT=$(top_srcdir)/tests/channel

APP=channel-test

include $(RTE_SDK)/mk/rte.vars.mk

include $(RTE_SDK)/mk/rte.cpuflags.mk

bin_PROGRAMS = channel-test

channel_test_SOURCES = channel-test.c

channel_test_CFLAGS = -m64 -pthread -march=native $(AM_CFLAGS)

channel_test_LDFLAGS = -m64 -pthread -march=native $(MACHINE_CFLAGS) $(AM_LDFLAGS)

channel_test_LDADD = $(top_srcdir)/src/libflowos.la
