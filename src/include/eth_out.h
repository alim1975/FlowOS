#ifndef __ETH_OUTPUT__
#define __ETH_OUTPUT__

#include <stdint.h>

#define ETHERNET_HEADER_LEN 14

int flowos_send_packet_burst(int nif);

struct rte_mbuf *flowos_eth_output(uint16_t type,
																	 int nif, 
																	 unsigned char* dst_mac, 
																	 uint16_t iplen);

#endif /* __ETH_OUTPUT__ */
