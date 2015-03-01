#include <string.h>
#include <netinet/ip.h>

#include "ip_in.h"
#include "tcp_in.h"
#include "mtcp_api.h"

#include "debug.h"

#define ETH_P_IP_FRAG   0xF800
#define ETH_P_IPV6_FRAG 0xF6DD

/*----------------------------------------------------------------------------*/
inline int ProcessIPv4Packet(mtcp_manager_t mtcp, uint32_t cur_ts, 
			     const int ifidx, unsigned char* pkt_data, int len)
{
  uint8_t *addr;
  /* check and process IPv4 packets */
  struct iphdr* iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
  int ip_len = ntohs(iph->tot_len);
  
  //printf("Process IPv4 packet tolat = %d ip_len= %d\n", len, ip_len) ;

  //addr = (uint8_t *) &iph->saddr;
  //printf("Source IP: %u.%u.%u.%u\n",
  //	 addr[0], addr[1], addr[2], addr[3]);

  //addr = (uint8_t *) &iph->daddr;
  //printf("Dest IP: %u.%u.%u.%u\n",
  //	 addr[0], addr[1], addr[2], addr[3]);

  //DumpIPPacket(mtcp, iph,  ip_len);

  /* drop the packet shorter than ip header */
  if (ip_len < sizeof(struct iphdr)) {
    printf("Packet length < IP header length\n");
    return ERROR;
  }
  if (ip_fast_csum(iph, iph->ihl)) {
    printf("IP checksum error\n");
    return ERROR;
  }
  
#if !PROMISCUOUS_MODE
  /* if not promiscuous mode, drop if the destination is not myself */
  if (iph->daddr != CONFIG.eths[ifidx].ip_addr)
    //DumpIPPacketToFile(stderr, iph, ip_len);
    return TRUE;
#endif
  
  // see if the version is correct
  if (iph->version != 0x4 ) {
    printf("Not an IPv4 packet, pass it to kernel \n");
    /*
    struct ps_packet packet;
    packet.ifindex = ifidx;
    packet.len = len;
    packet.buf = (char *)pkt_data;
    ps_slowpath_packet(mtcp->ctx->handle, &packet);
    */
    //TODO: pass packet back to kernel
    return FALSE;
  }
  
  switch (iph->protocol) {
  case IPPROTO_TCP:
    return ProcessTCPPacket(mtcp, cur_ts, iph, ip_len);
  default:
    /* currently drop other protocols */
    // printf("Only TCP packets are handled\n");
    return FALSE;
  }
  return FALSE;
}
/*----------------------------------------------------------------------------*/
