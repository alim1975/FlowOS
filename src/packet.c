#include <rte_mbuf.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <rte_mempool.h>

#include "packet.h"

static struct rte_mempool *packet_cache;

static int pkt_new = 0;
static int pkt_del = 0;

int packet_cache_init(void) {
  packet_cache = rte_mempool_create("flowos_packet_cache", 
				    POOL_SIZE,
				    sizeof(struct packet),
				    0, 0, /* cache, private */
				    /* ctor, ctorarg, dtor, dtorarg*/ 
				    NULL, NULL, NULL, NULL,
				    0, 0); /* CPU, flag */
  if(! packet_cache) return -1;
  
  return 0;
}

inline void packet_cache_delete(void)
{
  printf("FlowOS created %d packets, deletes %d packets\n", pkt_new, pkt_del);
  packet_cache = NULL;
}

struct packet *packet_create_dummy(void)
{
  struct packet *packet;
  if (rte_mempool_sc_get(packet_cache, (void **)&packet) != 0) {
    printf("packet_create(): failed to allocate memory\n");
    return NULL;
  }
  pkt_new++;
  packet->mbuf = NULL;
  packet->levels = 0;
  packet->seq = 0;
  packet->status = 0;
  //  TAILQ_INIT(&packet->list);
  return packet;
}

struct packet *packet_create(struct rte_mbuf *mbuf, uint8_t levels)
{
  struct packet *pkt;

  if(rte_mempool_sc_get(packet_cache, (void **)&pkt) != 0) {
    printf("packet_create(): failed to allocate memory\n");
    return NULL;
  }
  pkt_new++;
  pkt->mbuf = mbuf; 
  pkt->levels = levels;
  pkt->seq = 0;
  pkt->status = 0;
  pkt->sacked = 0;
  pkt->sack_ptr = NULL;
  pkt->sack_cnt = 0;
  //  TAILQ_INIT(&pkt->list);
  return pkt;
}

/* Delete data bytes from a TCP/UDP packet */
void packet_del_bytes(struct packet *pkt, char *from, int count)
{
  int len;
  char *ptr;
  uint16_t new_tlen;
  struct tcphdr *th;
  struct udphdr *uh;
  struct iphdr *ih = (struct iphdr *)packet_ip_header(pkt);
  th = NULL;
  uh = NULL;
  if (ih->protocol == IPPROTO_TCP) {
    th = (struct tcphdr *)packet_tcp_header(pkt);
    ptr = (char *)th + (th->doff << 2);
  }
  else if (ih->protocol == IPPROTO_UDP) {
    uh = (struct udphdr *)packet_tcp_header(pkt);
    ptr = (char *)uh + 8;
  }
  else {
    printf("packet_del_bytes(): No TCP/UDP header...\n");
    return;
  }
  /* TODO: complete this */
  if (from < ptr || ptr >= packet_end(pkt)) {
    printf("packet_del_bytes(): invalid offset value\n");
    return;
  }
  if (count > 0 && (packet_end(pkt) - from) < count) {
    printk("packet_del_bytes(): not enough bytes to delete\n");
    return;
  }
  pkt->status = 1; /* modified */
  //  pkt->mbuf->csum = 0;
  //  pkt->mbuf->ip_summed = CHECKSUM_NONE;
  /* delete everything after offset */ 
  if (count == -1 || (packet_end(pkt) - from) == count) {
    len = packet_end(pkt) - from;
    /* IP tot_len */
    ih->tot_len = htons(ntohs(ih->tot_len) - len);
    /* skb tail pointer */
    rte_pktmbuf_trim(pkt->mbuf, len);
    /* end pointer */
    packet_end(pkt) = (char *)ih + ntohs(ih->tot_len);
    /* TCP payload length */
    new_tlen = pkt->tlen - len; 
  }
  else { /* move data from offset + count upto end to offset */
    len = packet_end(pkt) - from - count;
    memmove(from, from + count, len);
    ih->tot_len = htons(ntohs(ih->tot_len) - count);
    rte_pktmbuf_trim(pkt->mbuf, count);
    packet_end(pkt) = (char *)ih + ntohs(ih->tot_len);
    new_tlen = pkt->tlen - count;
  }
  if (ih->protocol == IPPROTO_TCP) {
    th->check = 0; /* TCP checksum is invalid */
  }
  else { //UDP
    uh->check = 0;
    uh->len = htons(new_tlen + 8);
  }
}

inline void packet_delete(struct packet *packet) {
  if (packet) {
     rte_mempool_put(packet_cache, packet); 
     pkt_del++;
  }
}
