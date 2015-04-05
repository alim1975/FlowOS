#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <netinet/ip.h>
#include <rte_mbuf.h>

/* protocol types */
#define PTYPE_LLC 0
#define PTYPE_MAC 1
#define PTYPE_IP4 2
#define PTYPE_TCP 4
#define PTYPE_UDP 5

#define PROTO_HTTP 80

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_OFFSET
#define IP_OFFSET	0x1FFF
#endif

typedef char *(*decoder_fn) (struct rte_mbuf *, char *);
typedef char* string_t;

struct decoder {
  char protocol[12];
  decoder_fn decoder;
  TAILQ_ENTRY(decoder) list;
};
typedef struct decoder* decoder_t;

void register_decoder(decoder_t pdecoders,
		      decoder_fn decoder, 
		      string_t protocol);

void unregister_decoder(decoder_t pdecoders,
			string_t protocol);

decoder_fn 
find_protocol_decoder(decoder_t pdecoders,
		      string_t protocol);

uint32_t map_port_to_protocol(int sport, int dport);

int get_header_size(void *header, uint32_t protocol);

string_t tcp_flags_to_string(int flags);

string_t ipv4_decoder(struct rte_mbuf *mbuf, string_t prev);

string_t tcp_decoder(struct rte_mbuf *mbuf, string_t prev);

string_t udp_decoder(struct rte_mbuf *mbuf, string_t prev);

uint16_t compute_tcpudp_checksum(struct iphdr *iph, 
				   char*  payload,
				   string_t protocol);

#endif /*__PROTOCOL_H__*/
