#ifndef __ETH_OUT_H_
#define __ETH_OUT_H_

#include <stdint.h>

#include "flowos.h"

#define ETHERNET_HEADER_LEN 14

int flowos_send_packet_burst(flowos_t flowos, int nif);

struct rte_mbuf *flowos_eth_output(flowos_t flowos, 
				   uint16_t h_proto,
				   int nif, 
				   unsigned char* dst_mac, 
				   uint16_t iplen);

#endif /* __ETH_OUT_H_ */
