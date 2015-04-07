#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <rte_ether.h>

#include "protocol.h"
#include "packet.h"
#include "flowos.h"

/* install a protocol decoder to FlowOS */
void flowos_register_decoder(decoder_fn decoder, char *protocol) {
	decoder_t node;
	/* TODO: make sure that DECODER points valid function pointer */
	node = rte_malloc("node", sizeof(*node), 0);
	if (node == NULL) {
		printf("flowos_register_decoder(): failed to allocate memory\n");
		return;
	}
	node->decode = decoder;
	strcpy(node->protocol, protocol);
	TAILQ_INSERT_TAIL(&flowos.decoder_list, node, list);
}

/* remove a protocol decoder from FlowOS */
void flowos_unregister_decoder(char *protocol) {
	decoder_t node;
	TAILQ_FOREACH(node, &flowos.decoder_list, list) {
    if (strcasecmp(node->protocol, protocol) == 0) {
      TAILQ_REMOVE(&flowos.decoder_list, node, list);
      rte_free(node);
      break;
    }
  }
}

decoder_t flowos_find_decoder(char *protocol) {
	decoder_t node;
	TAILQ_FOREACH(node, &flowos.decoder_list, list) {
		if (strcasecmp(node->protocol, protocol) == 0) 
			return node;
	}
	return NULL;
}

/* compute TCP checksum */
/* uint16_t compute_tcpudp_checksum(struct iphdr *iph,  */
/* 																 unsigned char *payload, */
/* 																 uint8_t proto) { */
/*   uint16_t word; */
/*   uint16_t checksum;	 */
/*   uint16_t len; */
	
/*   /\* TCP segment size *\/ */
/*   len = ntohs(iph->tot_len) - (iph->ihl << 2); */
/*   checksum = rte_raw_cksum(payload, len); */
/*   word = csum_tcpudp_magic(iph->saddr,  */
/* 													 iph->daddr, len,  */
/* 													 proto, checksum); */
  
/*   return word; */
/* }  */

static char __tcp_flags__[32]; 
char *tcp_flags_to_string(int flags) {
  __tcp_flags__[0] = '\0'; 
  if (flags & TCP_FLAG_SYN)
    strcat(__tcp_flags__, "SYN ");
  if (flags & TCP_FLAG_FIN)
    strcat(__tcp_flags__, "FIN ");
  if (flags & TCP_FLAG_ACK)
    strcat(__tcp_flags__, "ACK ");
  if (flags & TCP_FLAG_RST)
    strcat(__tcp_flags__, "RST ");
  if (flags & TCP_FLAG_PSH)
    strcat(__tcp_flags__, "PSH ");
  if (flags & TCP_FLAG_URG)
    strcat(__tcp_flags__, "URG ");
  return __tcp_flags__;
}

char *ipv4_decoder(struct rte_mbuf *mbuf, char *prev) {
  char *iph = (char *) rte_pktmbuf_mtod(mbuf, char*) + sizeof(struct ether_hdr);
	return iph;
}

char *tcp_decoder(struct rte_mbuf *mbuf, char *prev) {
  struct iphdr *iph;

  iph = (struct iphdr *) ((char *) rte_pktmbuf_mtod(mbuf, char*) + sizeof(struct ether_hdr));
  if(iph->protocol == IPPROTO_TCP)
    return ((char *)iph + (iph->ihl << 2));
    
  return NULL;
}

char *udp_decoder(struct rte_mbuf *mbuf, char *prev) {
  struct iphdr *iph;

  iph = (struct iphdr *) ((char *) rte_pktmbuf_mtod(mbuf, char*) + sizeof(struct ether_hdr));
  if (iph->protocol == IPPROTO_UDP)
    return ((char *)iph + (iph->ihl << 2));

  return NULL;
}
 
/* compute TCP checksum */
uint16_t compute_tcpudp_csum(struct iphdr *iph, 
														 unsigned char *payload) {
  uint16_t word;
  uint32_t checksum;
  uint16_t len;

  /* TCP segment size */
  len = ntohs(iph->tot_len) - (iph->ihl << 2);
  checksum = len;  /* check sum of TCP segment */
  while (len > 1) {
    word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
    checksum += word;
    len -= 2;
    payload += 2;
  }
  /* sgement has 1 more byte */
  if (len > 0) checksum += (*payload << 8) & 0xFF00 ;
  /* IP source */
  payload = (uint8_t *)&iph->saddr;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word;
  payload += 2;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word;
  /* IP destination */
  payload = (uint8_t *)&iph->daddr;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word;
  payload += 2;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word; 
  /* IP protocol */
  checksum += iph->protocol;  
  while (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
  checksum = ~checksum;

  return checksum;
}

static uint16_t adjust_checksum(uint16_t csum, __be32 oldaddr, __be32 newaddr, int isudp)  {
  uint32_t sum = csum;

  /* as per RFC 768, 0 means no checksum was generated */
  if (isudp && csum == 0) return 0;
	
  /* add difference between upper/lower two address bytes */
  sum += ((oldaddr >> 16) & 0xFFFF) - ((newaddr >> 16) & 0xFFFF);
  sum += (oldaddr & 0xFFFF) - (newaddr & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum &= 0xFFFF;
  
  if (sum == 0) sum = 0xFFFF;
  
  return sum;
}

void fix_transport_header(struct packet *packet, __be32 oldaddr, __be32 newaddr) {
  int offset, flags;
  struct rte_mbuf *mbuf;
  struct iphdr *iph;
  struct tcphdr *tcp;	 
  struct udphdr *udp;	  
  
  mbuf = packet->mbuf;
  iph = (struct iphdr *) ((char *) rte_pktmbuf_mtod(mbuf, char *) + sizeof(struct ether_hdr));
  offset = ntohs(iph->frag_off);
  flags = offset & ~IP_OFFSET;
  offset &= IP_OFFSET;
  if ((flags & IP_MF) != 0 && offset == 0) {
    switch (iph->protocol) {
    case IPPROTO_UDP:
      udp = (struct udphdr*) ((char *)iph + (iph->ihl << 2));
      udp->check = adjust_checksum(udp->check, oldaddr, newaddr, 1);  
      break;
	  
    case IPPROTO_TCP:
      tcp = (struct tcphdr*) ((char *)iph + (iph->ihl << 2));
      tcp->check = adjust_checksum(tcp->check, oldaddr, newaddr, 0);   
      break;
    }
  }
}
