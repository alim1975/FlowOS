#ifndef __ETH_IN_H_
#define __ETH_IN_H_

#include <rte_mbuf.h>
#include "flowos.h"

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

int flowos_process_packet(flowos_t flowos, const int ifidx, uint32_t cur_ts, struct rte_mbuf *pkt);

#endif /* __ETH_IN_H_ */
