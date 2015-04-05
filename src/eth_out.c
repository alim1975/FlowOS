#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "dpdk.h"
#include "arp.h"
#include "eth_out.h"

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


extern int num_devices;
extern struct dpdk_device devices[MAX_DEVICES];

/*----------------------------------------------------------------------------*/
enum ETH_BUFFER_RETURN {BUF_RET_MAYBE, BUF_RET_ALWAYS};
/*----------------------------------------------------------------------------*/
int flowos_send_packet_burst(flowos_t flowos, int ifidx) {
  int ret = 0;

  return ret;
}
/*----------------------------------------------------------------------------*/
static inline 
struct rte_mbuf *flowos_get_tx_buffer(flowos_t flowos, 
				      int method, 
				      int ifidx, 
				      int len) {
  struct rte_mbuf *mbuf;
  // If interface index is not within configured range, return NULL
  if (ifidx < 0 || ifidx >= CONFIG.eths_num) {
    printf("Invalid interface index %d must be in [0 - %d]\n",
	   ifidx, CONFIG.eths_num);
    return NULL;
  }
  // If TX buffer pool is empty, return NULL
  // TODO: if method == BUF_RET_ALWAYS, drain TX queue 
  // to get a free buffer and return it.
  if (rte_mempool_get(flowos->tx_pool, (void **)&mbuf) != 0) {
    return NULL;
  }
  // ERROR: Packet buffer does not have 'len' bytes of free space, exit
  if (rte_pktmbuf_append(mbuf, len) == NULL) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_append(): error\n");
  }
  return mbuf;
}
/*----------------------------------------------------------------------------*/
struct rte_mbuf *flowos_eth_output(flowos_t flowos, 
				   uint16_t h_proto, 
				   int nif, 
				   unsigned char* dst_haddr, 
				   uint16_t iplen) {
  struct rte_mbuf *mbuf;
  struct ethhdr *ethh;
  int i;
  
  mbuf = flowos_get_tx_buffer(flowos, BUF_RET_MAYBE, nif, iplen + ETHERNET_HEADER_LEN);
  if (! mbuf) {
    printf("Failed to get available write buffer\n");
    return NULL;
  }
  ethh = (struct ethhdr *) rte_pktmbuf_mtod(mbuf, struct ethhdr *);
  for (i = 0; i < ETH_ALEN; i++) {
    ethh->h_source[i] = CONFIG.eths[nif].haddr[i];
    ethh->h_dest[i] = dst_haddr[i];
  }
  ethh->h_proto = htons(h_proto);
  
  return mbuf;
}
/*----------------------------------------------------------------------------*/
