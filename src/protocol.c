#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "protocol.h"
#include "packet.h"

/* install a protocol decoder to FlowOS */
void register_decoder(void *pdecoders,
		      decoder_fn decoder, 
		      char *protocol) {
    struct decoder *node;
    /* TODO: make sure that DECODER points 
       valid function pointer */
    node = rte_malloc("node", sizeof(struct node), 0);
    if (! node) {
      printf("register_decoder(): failed to allocate memory\n");
      return;
    }
    node->decoder = decoder;
    strcpy(node->protocol, protocol);
    TAILQ_INSERT_TAIL(pdecoders, node, list);
}

/* remove a protocol decoder from FlowOS */
void unregister_decoder(void *pdecoders,
			char *protocol) {
  struct list_head *ptr;
  struct list_head *pnext;
  struct decoder *node;

  list_for_each_safe(ptr, pnext, pdecoders){
    node = list_entry(ptr, struct decoder, list);
    if(strcasecmp(node->protocol, protocol) == 0){
      list_del(ptr);
      kfree(node);
      break;
    }
  }
}


/* compute TCP checksum */
uint16_t compute_tcpudp_checksum(struct iphdr *iph, 
				 unsigned char *payload,
				 u_char proto)
{
  uint16_t word;
  uint32_t checksum;	
  uint16_t len;

  /* TCP segment size */
  len = ntohs(iph->tot_len) - (iph->ihl << 2);  
  checksum = 0;
  checksum = csum_partial(payload, len, checksum);
  word = csum_tcpudp_magic(iph->saddr, 
			   iph->daddr, len, 
			   proto, checksum);
  
  return word;
} 
EXPORT_SYMBOL(compute_tcpudp_checksum);

static char __tcp_flags__[32]; 
char *tcp_flags_to_string(int flags)
{
  __tcp_flags__[0] = '\0'; 
  if(flags & TCP_FLAG_SYN)
    strcat(__tcp_flags__, "SYN ");
  if(flags & TCP_FLAG_FIN)
    strcat(__tcp_flags__, "FIN ");
  if(flags & TCP_FLAG_ACK)
    strcat(__tcp_flags__, "ACK ");
  if(flags & TCP_FLAG_RST)
    strcat(__tcp_flags__, "RST ");
  if(flags & TCP_FLAG_PSH)
    strcat(__tcp_flags__, "PSH ");
  if(flags & TCP_FLAG_URG)
    strcat(__tcp_flags__, "URG ");
  return __tcp_flags__;
}
EXPORT_SYMBOL(tcp_flags_to_string);

char *ipv4_decoder(struct sk_buff *skb, char *prev)
{
  return skb_network_header(skb);  
}

char *tcp_decoder(struct sk_buff *skb, char *prev)
{
  struct iphdr *iph;

  iph = (struct iphdr *)skb_network_header(skb);
  if(iph->protocol == IPPROTO_TCP)
    return ((char *)iph + (iph->ihl << 2));
    
  return NULL;
}

char *udp_decoder(struct sk_buff *skb, char *prev)
{
  struct iphdr *iph;

  iph = (struct iphdr *)skb_network_header(skb);
  if(iph->protocol == IPPROTO_UDP)
    return ((char *)iph + (iph->ihl << 2));

  return NULL;
}
 
/* compute TCP checksum */
uint16_t compute_tcpudp_csum(struct iphdr *iph, 
			     unsigned char *payload)
{
  uint16_t word;
  uint32_t checksum;
  uint16_t len;

  /* TCP segment size */
  len = ntohs(iph->tot_len) - (iph->ihl << 2);
  checksum = len;  /* check sum of TCP segment */
  while(len > 1){
    word = ((*payload << 8) & 0xFF00) + 
      (*(payload + 1) & 0xFF);
    checksum += word;
    len -= 2;
    payload += 2;
  }
  /* sgement has 1 more byte */
  if(len > 0)
    checksum += (*payload << 8) & 0xFF00 ;
  /* IP source */
  payload = (u8 *)&iph->saddr;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word;
  payload += 2;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word;
  /* IP destination */
  payload = (u8 *)&iph->daddr;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word;
  payload += 2;
  word = ((*payload << 8) & 0xFF00) + (*(payload + 1) & 0xFF);
  checksum += word; 
  /* IP protocol */
  checksum += iph->protocol;  
  while(checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
  checksum = ~checksum;

  return checksum;
}

static uint16_t adjust_checksum(uint16_t csum, __be32 oldaddr, __be32 newaddr, int isudp) 
{
  uint32_t sum = csum;

  /* as per RFC 768, 0 means no checksum was generated */
  if (isudp && csum == 0)	
    return 0;
	
  /* add difference between upper/lower two address bytes */
  sum += ((oldaddr >> 16) & 0xFFFF) - ((newaddr >> 16) & 0xFFFF);
  sum += (oldaddr & 0xFFFF) - (newaddr & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum &= 0xFFFF;
  
  if (sum == 0)
    sum = 0xFFFF;
  
  return sum;
}

void fix_transport_header(struct packet *packet, __be32 oldaddr, __be32 newaddr)
{
  int offset, flags;
  struct sk_buff *skb;
  struct iphdr *iph;
  struct tcphdr *tcp;	 
  struct udphdr *udp;	  
  
  skb = packet->skb;
  iph = (struct iphdr *)skb_network_header(skb);
  offset = ntohs(iph->frag_off);
  flags = offset & ~IP_OFFSET;
  offset &= IP_OFFSET;
  if((flags & IP_MF) != 0 && offset == 0){
    switch(iph->protocol){
    case IPPROTO_UDP:
      udp = (struct udphdr*)skb_transport_header(skb);
      udp->check = adjust_checksum(udp->check, oldaddr, newaddr, 1);  
      break;
	  
    case IPPROTO_TCP:
      tcp = (struct tcphdr*)skb_transport_header(skb);
      tcp->check = adjust_checksum(tcp->check, oldaddr, newaddr, 0);   
      break;
    }
  }
}
