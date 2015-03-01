#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

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

struct decoder {
  char protocol[12];
  decoder_fn decoder;
  TAILQ_ENTRY(decoder) list;
};

typedef TAILQ_HEAD(, decoder) decoder_list_t;

void register_decoder(struct decoder *pdecoders,
		      decoder_fn decoder, 
		      char *protocol);

void unregister_decoder(struct decoder *pdecoders,
			char *protocol);

decoder_fn 
find_protocol_decoder(struct decoder *pdecoders,
		      char *protocol);

uint32_t map_port_to_protocol(int sport, int dport);

int get_header_size(void *header, uint32_t protocol);

char *tcp_flags_to_string(int flags);

char *ipv4_decoder(struct rte_mbuf *mbuf, char *prev);

char *tcp_decoder(struct rte_mbuf *mbuf, char *prev);

char *udp_decoder(struct rte_mbuf *mbuf, char *prev);

uint16_t compute_tcpudp_checksum(struct iphdr *iph, 
				 u_char *payload,
				 u_char proto);

#endif /*_PROTOCOL_H_*/
