#ifndef __ETHIN__
#define __ETHIN__

#include <rte_mbuf.h>

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

typedef struct flowos* flowos_t;

int flowos_process_packet(flowos_t flowos, 
													int idx, 
													uint32_t cur_ts, 
													struct rte_mbuf *pkt);

#endif /* __ETHIN__ */
