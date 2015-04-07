#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#include "flowos.h"

#include "arp.h"

#ifdef RTE_EXEC_ENV_BAREMETAL
#define MAIN _main
#else
#define MAIN main
#endif

int MAIN(int argc, char **argv);

static struct rte_eth_conf eth_conf = { 
   .rxmode = { 
    .mq_mode = ETH_MQ_RX_RSS,
     .split_hdr_size = 0, 
     .header_split = 0, 
     .hw_ip_checksum = 1, 
     .hw_vlan_filter = 0, 
     .jumbo_frame = 0,
     .hw_strip_crc = 0, 
   }, 
   .rx_adv_conf = {
     .rss_conf = {
       .rss_key = NULL,
       .rss_hf = ETH_RSS_IP,
     },
   },
   .txmode = { 
     .mq_mode = ETH_MQ_TX_NONE, 
   }, 
 }; 

static struct rte_eth_txconf tx_conf = {
  .tx_thresh = {
    .pthresh = 36,
    .hthresh = 0,
    .wthresh = 0,
  },
  .tx_rs_thresh = 0,
  .tx_free_thresh = 0,
  //.txq_flags = (ETH_TXQ_FLAGS_NOMULTSEGS |
  //		ETH_TXQ_FLAGS_NOVLANOFFL |
  //		ETH_TXQ_FLAGS_NOXSUMSCTP |
  //		ETH_TXQ_FLAGS_NOXSUMUDP  |
  //		ETH_TXQ_FLAGS_NOXSUMTCP)
};

static struct rte_eth_rxconf rx_conf = {
  .rx_thresh = {
    .pthresh = 8,
    .hthresh = 8,
    .wthresh = 4,
  },
  .rx_free_thresh = 64,
  .rx_drop_en = 0,
};

static void flowos_init_dpdk(int argc, char **argv) {
  uint8_t count;

  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("FlowOS: failed to initialize DPDK\n");

	flowos.cpu_count = rte_lcore_count();

  flowos.device_count = rte_eth_dev_count();
  if (flowos.device_count <= 0) 
    rte_exit(EXIT_FAILURE, "FlowOS: no DPDK enabled interface found\n");

  printf("FlowOS: found %d DPDK enabled NIC ports.\n", flowos.device_count);
  /* init RX/TX buffer pools */
  unsigned cpu = rte_lcore_id();
  unsigned socketid = rte_lcore_to_socket_id(cpu);
  flowos.rx_pool = 
    rte_mempool_create("rx_pool", POOL_SIZE * flowos.device_count, 
											 MAX_PKT_SIZE, CACHE_SIZE,
											 sizeof (struct rte_pktmbuf_pool_private),
											 rte_pktmbuf_pool_init, NULL,
											 rte_pktmbuf_init, NULL, socketid, 0);
  if (flowos.rx_pool == NULL) {
    rte_exit(EXIT_FAILURE, "FlowOS: failed to create RX buffer pool.\n");
  }
	
  flowos.tx_pool = 
    rte_mempool_create("tx_pool", POOL_SIZE * flowos.device_count,
											 MAX_PKT_SIZE, CACHE_SIZE,
											 sizeof (struct rte_pktmbuf_pool_private),
											 rte_pktmbuf_pool_init, NULL,
											 rte_pktmbuf_init, NULL, socketid, 0);
  if (flowos.tx_pool == NULL) {
    rte_exit(EXIT_FAILURE, "FlowOS: failed to create TX buffer pool.\n");
  }
}

static void flowos_config_devices() {
  int i, ret, ifidx;
  struct rte_eth_link link;
  /* struct rte_eth_conf eth_conf; */
  unsigned cpu = rte_lcore_id();
  unsigned socketid = rte_lcore_to_socket_id(cpu);
	// Retrieve interface information from DPDK
	flowos_set_device_info();
	// Configure IP addresses
	flowos_config_interfaces("config/interfaces");
	flowos_print_interface_info();

  /* attaching (device, queue) */
  for (i = 0; i < flowos.device_count; i++) {
		if (flowos.devices[i].configured) {
			ret = rte_eth_dev_configure(i, NB_RX_QUEUE, NB_TX_QUEUE, &eth_conf);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE, "FlowOS: failed to configure device: eth%d\n", i);
			}
			/* TODO: uses constatnt RX/TX ring descriptors, assumes devices use only one queue = 0 */ 
			ret = rte_eth_tx_queue_setup(i, 0, NB_TX_DESC, socketid, &tx_conf);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE, "FlowOS failed to setup TX queue for eth%d\n", i);
			}
			//printf("If %d rte_eth_tx_queue_setup() successful\n", ifidx);
			ret = rte_eth_rx_queue_setup(i, 0, NB_RX_DESC, socketid, &rx_conf, flowos.rx_pool);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE, "FlowOS failed to setup RX queue for eth%d\n", i);
			}
			//printf("If %d rte_eth_rx_queue_setup() successful\n", i);
			ret = rte_eth_dev_start(i);
			if (ret < 0) {
				rte_exit(EXIT_FAILURE, "FlowOS failed to start eth%d\n", i);
			}
			//printf("If %d rte_eth_dev_start() successful\n", i);
			rte_eth_link_get(i, &link);
			if (link.link_status == 0) {
				rte_exit(EXIT_FAILURE, "DPDK interface is down: %d\n", i);
			}
			printf("Interface eth%d is UP and RUNNING\n", i);
			rte_eth_promiscuous_enable(i);
		}
		else {
			printf("FlowOS: interface eth%d is not configured\n", i);
		}
	}
}

int flowos_set_device_info() {
  struct rte_eth_dev_info dev_info;
  struct ether_addr mac_addr;
  int eidx = 0;
  int i, j;
  
  printf("FlowOS: loading interface setting\n");  
  for (i = 0; i < flowos.device_count; i++) {
    rte_eth_dev_info_get(i, &dev_info);
    flowos.devices[i].configured = 0; 
    printf("FlowOS: device index: %d == i(%d)\n", dev_info.if_index, i);
    /* Name*/
    sprintf(flowos.devices[i].name, "eth%d", i);
    /* MAC address */
    rte_eth_macaddr_get(i, &mac_addr);
    for (j = 0; j < ETH_ALEN; j++) {
      flowos.devices[i].mac_addr[j] = mac_addr.addr_bytes[j];
    }
  }  
  // TODO: handle multiple queues per interface
  // num_queues = GetNumQueues();
  flowos.q_count = NB_RX_QUEUE;
  if (flowos.q_count <= 0) {
    printf("Failed to find NIC queues!\n");
    return -1;
  }
  if (flowos.q_count > flowos.cpu_count) {
    printf("Too many NIC queues available.\n");
    return -1;
  }
  
  return 0;
}

int flowos_xmit_packets() {
	int i;
	for (i = 0; i < flowos.device_count; i++) {
    if (flowos.devices[i].configured) {
			//if (flowos.tx_queue[idx]) {
				//tx_burst...
			//}
		}
  } 
}

int flowos_tcp_input(flow_t flow, struct rte_mbuf *mbuf) {
  return -1;
}

inline void flowos_insert_flow(flow_t flow) {
	TAILQ_INSERT_TAIL(&flowos.flow_list, flow, list);
}

inline void flowos_remove_flow(flow_t flow) {
	TAILQ_REMOVE(&flowos.flow_list, flow, list);
}

int MAIN(int argc, char **argv) {
  int i, j, ret, recv_cnt, ifidx = 0;
  struct timeval cur_ts;
  uint8_t count;
  uint32_t ts;
  long pktcount = 0;
  struct rte_eth_link link;
  struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
  /* initialize DPDK */
  flowos_init_dpdk(argc, argv);
  /* Configure NICs */
  flowos_config_devices();
  /* Configure ARP table */
  flowos_config_arp_table("config/arp.conf");
  /* Configure routing table */
  flowos_config_routing_table("config/route.conf");
  /* Start TCP thread */
  //flowos_start_tcp();
  /* Init task scheduler */
  task_pool_create(1024);
  scheduler_init(2);
  /* main loop: process packets */
  while (! flowos.done) {
    //STAT_COUNT(flowos.runstat.rounds);
    recv_cnt = 0;
    gettimeofday(&cur_ts, NULL);
    ts = TIMEVAL_TO_TS(&cur_ts);
    //flowos.cur_ts = ts;
    //STAT_COUNT(flowos.runstat.rounds_rx_try);
    /* Read packets into rx_mbufs from NIC */    
    //printf("Read packets into rx_mbufs from NIC\n");
    for (i = 0; i < flowos.device_count; i++) {
      if (flowos.devices[i].configured) {
				//printf("FlowOS reding packet from interface %d\n", i);
				int idx = i;
				recv_cnt = rte_eth_rx_burst(idx, 0 /* queue_id*/, rx_mbufs, MAX_PKT_BURST);
				if (recv_cnt < 0) {
					if (errno != EAGAIN && errno != EINTR) {
						perror("FlowOS: RX");
						rte_exit(EXIT_FAILURE, "FlowOS: failed to retrieve packets from eth%d", i);
					}
				}
				else if (recv_cnt > 0) {
					//printf("FlowOS received %d packets from interface %d\n", recv_cnt, idx);
					for (j = 0; j < recv_cnt; j++) {
						struct ether_hdr *eh = (struct ether_hdr *)rte_pktmbuf_mtod(rx_mbufs[j], struct ether_hdr *);
						int type = ntohs(eh->ether_type);
						if (type == ETHER_TYPE_IPv4) {
							//printf("FlowOS: processing IP packet\n");
							ret = flowos_process_ipv4_packet(ts, idx, rx_mbufs[j]);
						} 
						else if (type == ETHER_TYPE_ARP) {
							//printf("FlowOS: process ARP packet\n");
							flowos_process_arp_packet(ts, idx, rx_mbufs[j]);
						} 
						else {
							printf("FlowOS received unknown packet, dropping.\n");
							rte_pktmbuf_free(rx_mbufs[j]);
						}
					}
				}
				//if (recv_cnt > 0) STAT_COUNT(flowos.runstat.rounds_rx);
			}
		}
    // Send out packets waiting at TX queues
    flowos_xmit_packets();
  } 
  return 0;
}
