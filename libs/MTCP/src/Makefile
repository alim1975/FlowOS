.PHONY: clean

### TARGET ###
MTCP_LIB_DIR=../lib
MTCP_LIB=libmtcp.a

MTCP_HDR_DIR=../include
MTCP_HDR = mtcp_api.h mtcp_epoll.h


### GCC ###
GCC = gcc
GCC_OPT = -m64 -Wall -fPIC -D_GNU_SOURCE

#DBG_OPT = -DDBGMSG -DDBGFUNC -DSTREAM -DSTATE -DTSTAT -DAPP -DEPOLL
#DBG_OPT += -DPKTDUMP
#DBG_OPT += -DDUMP_STREAM
#GCC_OPT += -g -DNETSTAT -DINFO -DDBGERR -DDBGCERR
GCC_OPT += -DNDEBUG -O3 -DNETSTAT -DINFO -DDBGERR -DDBGCERR
GCC_OPT += $(DBG_OPT)


### LIBRARIES AND INCLUDES ###
INC_DIR=./include
INC= -I$(INC_DIR)

LIBS = -lnuma -lpthread -lrt

# DPDK LIBRARY and HEADER
DPDK_DIR=../../dpdk
LIB_DIR = -L$(DPDK_DIR)/build/lib
INC += -I$(DPDK_DIR)/build/include

ifeq ($(wildcard /usr/lib/libhugetlbfs.so),) 
else
	GCC_OPT += -DHUGEPAGE
endif


### SOURCE CODE ###
SRCS = core.c tcp_stream.c api.c eventpoll.c socket.c pipe.c \
	   tcp_util.c tcp_in.c tcp_out.c \
	   timer.c cpu.c rss.c addr_pool.c fhash.c memory_mgt.c logger.c debug.c \
	   tcp_rb_frag_queue.c tcp_ring_buffer.c tcp_send_buffer.c tcp_sb_queue.c tcp_stream_queue.c

OBJS = $(patsubst %.c,%.o,$(SRCS))
DEPS = $(patsubst %.c,.%.d,$(SRCS))


### GOALS ###
default: $(OBJS) $(MTCP_HDR)
	mkdir -p $(MTCP_LIB_DIR)
	ar rvs $(MTCP_LIB_DIR)/$(MTCP_LIB) $(OBJS)

$(OBJS): %.o: %.c Makefile
	$(GCC) $(GCC_OPT) $(INC) -c $< -o $@

$(DEPS): .%.d: %.c Makefile
	$(GCC) $(GCC_OPT) $(INC) -MM $(CFLAGS) $< > $@

-include $(DEPS)

$(MTCP_HDR):
	cp $(INC_DIR)/$@ $(MTCP_HDR_DIR)/$@

clean: clean-library
	rm -f *.o *~ core
	rm -f .*.d

clean-library:
	rm -f $(MTCP_LIB_DIR)/*
	rm -f $(MTCP_HDR_DIR)/*
