#include <rte_ether.h>

#include "ip_in.h"
#include "eth_in.h"
#include "arp.h"

/*---------------------------------------------------------------------*/
int flowos_process_packet(flowos_t flowos, 
													int idx, 
													uint32_t cur_ts, 
													struct rte_mbuf *pkt) {
  int ret;
  struct ether_hdr *ethh;

	printf("FlowOS: process_packet() packet from interface %d\n", idx);

	ethh = (struct ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr *);

  u_short ip_proto = ntohs(ethh->ether_type);

  int len = rte_pktmbuf_data_len(pkt);

#ifdef PKTDUMP
  DumpPacket(mtcp, (char *)ethh, len, "IN", idx);
#endif
  
#ifdef NETSTAT
  mtcp->nstat.rx_packets[idx]++;
  mtcp->nstat.rx_bytes[idx] += len + 24;
#endif /* NETSTAT */
  /*
  printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
	 ethh->h_source[0],
	 ethh->h_source[1],
	 ethh->h_source[2],
	 ethh->h_source[3],
	 ethh->h_source[4],
	 ethh->h_source[5]);

  printf("Dest MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
	 ethh->h_dest[0],
	 ethh->h_dest[1],
	 ethh->h_dest[2],
	 ethh->h_dest[3],
	 ethh->h_dest[4],
	 ethh->h_dest[5]);
  */
  /* process ipv4 packet */
  if (ip_proto == ETHER_TYPE_IPv4) {
		printf("FlowOS: process IP packet\n");
    ret = flowos_process_ipv4_packet(cur_ts, idx, pkt);
  } 
  else if (ip_proto == ETHER_TYPE_ARP) {
		printf("FlowOS: process ARP packet\n");
    flowos_process_arp_packet(cur_ts, idx, pkt);
    return TRUE;
  } 
  else {
    printf("flowos_process_packet() unknown packet\n");
    //DumpPacket((char *)ethh, len, "??", ifidx);
    rte_pktmbuf_free(pkt);  
    return FALSE;
  }
  
#ifdef NETSTAT
  if (ret < 0) {
    mtcp->nstat.rx_errors[idx]++;
  }
#endif

  return ret;
}
