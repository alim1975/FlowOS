#ifndef __FOS_PACKET__
#define __FOS_PACKET__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#define MAX_LEVELS 8
#define POOL_SIZE 10000

struct packet {
  uint8_t levels;
  char *parray[MAX_LEVELS];
  uint32_t seq;
  uint8_t status;
  struct rte_mbuf *mbuf;
  /* used by TCP flows only */
  uint32_t tseq;    /* TCP seq */
  uint32_t tack;    /* TCP ack */
  uint32_t tseq_in  /* for seq map */;
  uint32_t tseq_out /* for seq map */;
  uint16_t tlen;    /* TCP payload len */
  uint32_t tsval;   /* TCP time stamp */
  uint32_t tsecr;   /* TS Echo Reply */
  uint8_t  *sack_ptr; /* SACK blocks begin */
  uint8_t  sack_cnt; /* number of SACK blocks */
  uint8_t  sacked;   /* packet was SACKed (RFC2018) */
  TAILQ_ENTRY(packet) list;
};

typedef struct packet* packet_t;

#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFF
#endif

#define SEQ_GT(s1, s2)					\
  (((s1 > s2) && (s1 - s2 <= UINT32_MAX / 2)) ||	\
   ((s2 > s1) && (s2 - s1 > UINT32_MAX / 2)))

/* assumes parray[0] == IP */
#define packet_ip_header(packet)  ((struct iphdr *)(packet)->parray[0])

/* assumes parray[1] == TCP */
#define packet_tcp_header(packet) ((struct tcphdr *)(packet)->parray[1])

/* assumes parray[1] == UDP */
#define packet_udp_header(packet) ((struct udphdr *)(packet)->parray[1])

/* pointer to first byte */
#define packet_start(packet, level) (packet)->parray[level]

/* pointer to last byte */
#define packet_end(packet) (packet)->parray[(packet)->levels - 1]

/* IP packet size */
#define packet_ip_totalbytes(packet) \
  ((packet)->parray[(packet)->levels - 1] - (packet)->parray[0])

/* IP payload size */
#define packet_tcp_totalbytes(packet) \
  ((packet)->parray[(packet)->levels - 1] - (packet)->parray[1])

/* TCP payload size */
#define packet_tcp_payload(iph, tcph) \
  (ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2))

int packet_cache_init(void);

void packet_cache_delete(void);

struct packet *packet_create_dummy(void);

struct packet *packet_create(struct rte_mbuf *mbuf, uint8_t levels);

void packet_del_bytes(struct packet *pkt, char *from, int count);

void packet_delete(struct packet *pkt);

#endif // __FOS_PACKET__
