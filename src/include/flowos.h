/** Copyright (c) 2011 M. Abdul Alim, Lancaster University 
 * FlowOS main header file 
 */
#ifndef __FLOWOS__
#define __FLOWOS__

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

//#include "pmodule.h"
#include "flow.h"
#include "protocol.h"
//#include "cmdline.h"
#include "dpdk.h"

#define HZ		1000
#define TIME_TICK	(1000000/HZ)  // in us
#define TIMEVAL_TO_TS(t) (uint32_t)((t)->tv_sec * HZ + ((t)->tv_usec / TIME_TICK))

#define TS_TO_USEC(t)	((t) * TIME_TICK)
#define TS_TO_MSEC(t)	(TS_TO_USEC(t) / 1000)

#define USEC_TO_TS(t)	((t) / TIME_TICK)
#define MSEC_TO_TS(t)	(USEC_TO_TS((t) * 1000))

#define SEC_TO_USEC(t)	((t) * 1000000)
#define SEC_TO_MSEC(t)	((t) * 1000)
#define MSEC_TO_USEC(t)	((t) * 1000)
#define USEC_TO_SEC(t) 	((t) / 1000000)

#define TCP_TIMEWAIT 0
#define TCP_TIMEOUT  (MSEC_TO_USEC(30000) / TIME_TICK)	// 30s

#define MAX_PKT_SIZE (2*1024 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define NB_RX_QUEUE 1

#define NB_TX_QUEUE 1

#define	NB_RX_DESC 128

#define	NB_TX_DESC 128

#define CACHE_SIZE 64

/* struct eth_table { */
/*   char dev_name[128]; */
/*   int ifindex; */
/*   int stat_print; */
/*   unsigned char haddr[ETH_ALEN]; */
/*   uint32_t netmask; */
/*   uint32_t ip_addr; */
/* }; */

struct route_table {
  uint32_t daddr;
  uint32_t mask;
  uint32_t masked;
  int prefix;
  int nif;
};

struct arp_entry {
  uint32_t ip;
  int8_t prefix;
  uint32_t ip_mask;
  uint32_t ip_masked;
  unsigned char haddr[ETH_ALEN];
};

struct arp_table {
  struct arp_entry *entry;
  int entries;
};

struct tcpconf {
	int num_cpus;

  int max_concurrency;  
  int max_num_buffers;

  int rcvbuf_size;
  int sndbuf_size;
  
  int tcp_timewait;
  int tcp_timeout;
};

/* the main data structure of FlowOS */
struct flowos {
  int done;
  /* list of flows */
  TAILQ_HEAD(, flow) flows;  
  /* list of decoders */
  TAILQ_HEAD(, decoder) decoders;
	/* FlowOS stats */
  unsigned long pktprocessed;
  unsigned long pktdropped;
	/* CPU cores dedicated for FlowOS */
  int cpu_count;
	/* Pre-allocated packets for RX and TX */
  struct rte_mempool *rx_pool;
  struct rte_mempool *tx_pool;
	/* interface config */
  int q_count;
  int device_count;
  struct dpdk_device devices[MAX_DEVICES];
	/* TX ring for each device */
  struct dpdk_burst tx_burst[MAX_DEVICES];

	/* ARP table */
	struct arp_table arp;
  /* routing table */
  int routes;	            /* # of entries */
  struct route_table *rt;	/* routing table */  	

	/* TCP configuration */
	struct tcpconf tcp;
};
typedef struct flowos* flowos_t;

struct flowos flowos;

/* extern int          udp_encap_init(void); */
/* extern void         udp_encap_close(void); */

/* int                 flowos_xmit_mbuf(struct flow *flow, struct rte_mbuf *mbuf); */
/* extern int          flowos_send_message(struct flowos_msghdr *); */
/* extern int          flowos_send_response(const struct flowos_msghdr *, uint8_t, char *, size_t); */

/* void                flowos_release_data(struct flowos_pm *pm, struct streamp *tail); */
 
/* void                flowos_release_packet(struct flowos_pm *thread, struct packet *pkt); */

int                 is_flow_table_empty(void);
void                flowos_insert_flow(flow_t flow);
void                flowos_remove_flow(flow_t flow);

int                 flowos_tcp_input(flow_t flow, struct rte_mbuf *mbuf);
#endif /* __FLOWOS__ */
