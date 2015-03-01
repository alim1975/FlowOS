#ifndef __IP_IN_H_
#define __IP_IN_H_

#include <rte_mbuf.h>
#include "flowos.h"

int flowos_process_ip_packet(flowos_t flowos, uint32_t cur_ts,
		      const int nif, rte_pktmbuf* pkt);

#endif /* __IP_IN_H_ */
