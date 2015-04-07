#ifndef __IPINPUT__
#define __IPINPUT__

#include <rte_mbuf.h>

int flowos_process_ipv4_packet(uint32_t cur_ts,
															 const int nif, 
															 struct rte_mbuf* pkt);

#endif /* __IPINPUT__ */
