#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "arp.h"
#include "eth_out.h"
#include "flowos.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define MAX_WINDOW_SIZE 65535

/*----------------------------------------------------------------------------*/
enum ETH_BUFFER_RETURN {BUF_RET_MAYBE, BUF_RET_ALWAYS};

// needs locking
/*----------------------------------------------------------------------------*/
int flowos_send_packet_burst(int idx) {
  int i, ret = 0, dropped = 0;
	assert(idx >= 0 && idx < flowos.device_count);
	if (flowos.tx_burst[idx].cnt > 0) {
		ret = rte_eth_tx_burst(flowos.tx_burst[idx].queue.ifindex,
													 flowos.tx_burst[idx].queue.qidx,
													 flowos.tx_burst[idx].mbufs,
													 flowos.tx_burst[idx].cnt);		
		if (ret <= 0) {
			printf("rte_eth_tx_burst() failed to send bursts" 
						 " of %d packets on eth%d.\n",
						 flowos.tx_burst[idx].cnt, idx);
			return ret;
		}
		else {
			dropped = flowos.tx_burst[idx].cnt - ret;
			flowos.tx_burst[idx].cnt = dropped;
			for (i = 0; i < dropped; i++) {
				flowos.tx_burst[idx].mbufs[i] = flowos.tx_burst[idx].mbufs[ret + i];
			}
		}
	}
  return ret;
}
/*----------------------------------------------------------------------------*/
static inline 
struct rte_mbuf *flowos_get_tx_buffer(int method, int idx, int len) {
  struct rte_mbuf *mbuf;
  // If interface index is not within configured range, return NULL
  if (idx < 0 || idx >= flowos.device_count) {
    printf("Invalid interface index %d must be in [0 - %d]\n",
					 idx, flowos.device_count - 1);
    return NULL;
  }
  // If TX buffer pool is empty, return NULL
  // TODO: if method == BUF_RET_ALWAYS, drain TX queue 
  // to get a free buffer and return it.
	// NEEDS LOCKING
  if (rte_mempool_get(flowos.tx_pool, (void **)&mbuf) != 0) {
		if (method == BUF_RET_MAYBE) return NULL;
		else {
			if (flowos_send_packet_burst(idx) <= 0) return NULL;
		}
  }
  // ERROR: Packet buffer does not have 'len' bytes of free space, exit
  if (rte_pktmbuf_append(mbuf, len) == NULL) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_append(): error\n");
  }
  return mbuf;
}
/*----------------------------------------------------------------------------*/
struct rte_mbuf *flowos_eth_output(uint16_t type, 
																	 int nif, 
																	 unsigned char* dst_haddr, 
																	 uint16_t iplen) {
  struct rte_mbuf *mbuf;
  struct ethhdr *ethh;
  int i;
	if (nif < 0 || nif >= flowos.device_count) {
		printf("FlowOS: invalid interface index\n");
		return NULL;
	}
	
  mbuf = flowos_get_tx_buffer(BUF_RET_MAYBE, nif, iplen + ETHERNET_HEADER_LEN);
  if (! mbuf) {
    printf("Failed to get available write buffer\n");
    return NULL;
  }
  ethh = (struct ethhdr *) rte_pktmbuf_mtod(mbuf, struct ethhdr *);
  for (i = 0; i < ETH_ALEN; i++) {
    ethh->h_source[i] = flowos.devices[nif].mac_addr[i];
    ethh->h_dest[i] = dst_haddr[i];
  }
  ethh->h_proto = htons(type);
  
  return mbuf;
}
/*----------------------------------------------------------------------------*/
