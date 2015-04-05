include $(top_srcdir)/config.mk

RTE_SDK = $(top_srcdir)/libs/dpdk
RTE_ARCH = x86_64-native-linuxapp-gcc
RTE_TARGET = build
APP = FlowOS

include $(RTE_SDK)/mk/rte.vars.mk
include $(RTE_SDK)/mk/rte.cpuflags.mk

bin_PROGRAMS = FlowOS

lib_LTLIBRARIES = libflowos.la

libflowos_la_LDFLAGS = -all-static

libflowos_la_SOURCES = config.c packet.c eth_in.c eth_out.c arp.c ip_in.c scheduler.c task.c channel.c 

FlowOS_SOURCES = flowos.c

FlowOS_CFLAGS = -m64 -pthread -march=native $(AM_CFLAGS)

FlowOS_LDFLAGS = -m64 -pthread -march=native $(MACHINE_CFLAGS) $(AM_LDFLAGS)

FlowOS_LDADD = libflowos.la 
