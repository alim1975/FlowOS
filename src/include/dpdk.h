#ifndef __DPDK__
#define __DPDK__

#include<rte_mbuf.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define MAX_DEVICES 16

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MAX_PKT_BURST 256
#define MAX_PACKET_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

struct dpdk_device {
  char name[IFNAMSIZ];
  char mac_addr[ETH_ALEN]; // MAC address
  uint32_t ip_addr;        // network order
  uint32_t netmask;        // network order
  int configured;          // port configured
  int num_rx_queues;
  int num_tx_queues;
};

struct dpdk_queue {
  int ifindex;
  int qidx;
};

struct dpdk_burst {
  int cnt;
  int recv_blocking;
  struct dpdk_queue queue;
  struct rte_mbuf *mbufs[MAX_PKT_BURST];
};

static inline unsigned int ip_fast_csum(const void *iph, unsigned int ihl)
{
  unsigned int sum;
  
  asm("  movl (%1), %0\n"
      "  subl $4, %2\n"
      "  jbe 2f\n"
      "  addl 4(%1), %0\n"
      "  adcl 8(%1), %0\n"
      "  adcl 12(%1), %0\n"
      "1: adcl 16(%1), %0\n"
      "  lea 4(%1), %1\n"
      "  decl %2\n"
      "  jne      1b\n"
      "  adcl $0, %0\n"
      "  movl %0, %2\n"
      "  shrl $16, %0\n"
      "  addw %w2, %w0\n"
      "  adcl $0, %0\n"
      "  notl %0\n"
      "2:"
      /* Since the input registers which are loaded with iph and ih
	 are modified, we must also specify them as outputs, or gcc
	 will assume they contain their original values. */
      : "=r" (sum), "=r" (iph), "=r" (ihl)
      : "1" (iph), "2" (ihl)
      : "memory");
  return sum & 0xffff;
}

#define NID_ZERO(isp)    (isp = 0)
#define NID_SET(id, isp) (isp |= 1 << id)
#define NID_CLR(id, isp) (isp &= ~(1 << id))
#define NID_ISSET(id, isp)   (isp & (1 << id))

// maximum number of interface descriptor is 16
typedef uint16_t nids_set;
struct dpdk_event {
	long timeout;	
	int qidx;
	nids_set rx_nids;
	nids_set tx_nids;
};
#endif /* __DPDK__ */
