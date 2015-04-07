#include <rte_ether.h>

#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "ip_in.h"
//#include "tcp_in.h"
//#include "mtcp_api.h"
#include "flow.h"
#include "flowos.h"

//#include "debug.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD

/*----------------------------------------------------------------------------*/
int flowos_process_ipv4_packet(uint32_t cur_ts, 
															 const int idx, 
															 struct rte_mbuf *pkt) {
  flow_t flow = NULL;
  /* check and process IPv4 packets */
  struct iphdr* iph = (struct iphdr *) 
    ((char *)rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr));
  int ip_len = ntohs(iph->tot_len);

  //DumpIPPacket(mtcp, iph,  ip_len);

  /* drop the packet shorter than ip header */
  if (ip_len < sizeof(struct iphdr)) {
    printf("Packet length < IP header length\n");
    rte_pktmbuf_free(pkt);
    return -1;
  }
	/* drop the packet if IP checksum is incorrect */
  if (ip_fast_csum(iph, iph->ihl)) {
    printf("IP checksum error\n");
    rte_pktmbuf_free(pkt);
    return -1;
  }
	/* if not promiscuous mode, drop if the destination is not myself */
#if !PROMISCUOUS_MODE
  if (iph->daddr != flowos.devices[idx].ip_addr) {
		uint8_t *ip = &iph->daddr;
    printf("IP packet %u.%u.%u.%u is not this host address\n", 
					 ip[0], ip[1], ip[2], ip[3]);
    //DumpIPPacketToFile(stderr, iph, ip_len);
    rte_pktmbuf_free(pkt);
		return -1;
	}
#endif  
  /* see if the version is correct */
  if (iph->version != 0x04 ) {
    printf("Not an IPv4 packet, discarding.\n");
    rte_pktmbuf_free(pkt);
    return -1;
  }
	/* find the flow this packet belongs to */
	printf("FlowOS: classify packet...\n");
  flow = flowos_classify_packet(pkt);
  if (! flow) {
    printf("FlowoS: flow table is empty, discarding packet\n");
    rte_pktmbuf_free(pkt);
    return -1; /* No matching flow, pass it to the kernel */
  }
	/* if packet belongs to a TCP flow, handle TCP connection management */
  if (is_tcp_flow(flow)) { 
    if (flowos_tcp_input(flow, pkt) != 0) {
      printf("FlowOS: TCP input error, discarding packet.\n");
      rte_pktmbuf_free(pkt);
      return -1;
    }
  }
	/* if packet belongs to a non-TCP flow, dispatch packet to flow */
  else { 
    if (flow_append_packet(flow, pkt) != 0) {
      printf("FlowOS: failed to append packet to flow, discarding packet.\n");
      rte_pktmbuf_free(pkt);
      return -1;
    }
  }
  return 0;
}
/*----------------------------------------------------------------------------*/
