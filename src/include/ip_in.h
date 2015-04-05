#ifndef __IP_IN_H__
#define __IP_IN_H__

#include <rte_mbuf.h>

typedef struct flowos* flowos_t;

int flowos_process_ip_packet(flowos_t flowos, 
			     uint32_t cur_ts,
			     const int nif, 
			     struct rte_mbuf* pkt);

#endif /* __IP_IN_H__ */
