#ifndef __IP_OUT_H_
#define __IP_OUT_H_

#include <stdint.h>
#include "flowos.h"

inline int get_output_interface(uint32_t daddr);

void flowos_send_ip_packet(flowos_t flowos, int nif_in, struct rte_pktmbuf *mbuf);

uint8_t *flowos_send_ip_packet_standalone(flowos_t flowos,
			    uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t tcplen);

struct rte_pktmbuf *flowos_ip_output(flowos_t flowos, tcp_stream *stream, uint16_t tcplen);

#endif /* __IP_OUT_H_ */
