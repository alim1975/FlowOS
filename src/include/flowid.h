#ifndef __FLOWID_H__
#define __FLOWID_H__

#include <stdint.h>
#include <netinet/in.h>
#include <linux/ip.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IF_NAMSIZ
#define IF_NAMSIZ 16
#endif

/* Input port */
#define FLOWOS_IN_PORT 0x1
/* Ethernet source address. */
#define FLOWOS_MAC_SRC 0x2
/* Ethernet destination address. */
#define FLOWOS_MAC_DST 0x4
/* IPv4 source address */
#define FLOWOS_IPv4_SRC 0x8
/* IPv4 destination address */
#define FLOWOS_IPv4_DST 0x10
/* TCP source port. */
#define FLOWOS_TCP_SRC 0x20
/* TCP destination port. */
#define FLOWOS_TCP_DST 0x40
/* UDP source port. */
#define FLOWOS_UDP_SRC 0x80
/* UDP destination port. */
#define FLOWOS_UDP_DST 0x100

/* Describe a flow using these fields */
struct flowid {
  uint16_t fields;           /* Wildcard fields. */
  uint8_t mac_src[ETH_ALEN]; /* Ethernet source address. */
  uint8_t mac_dst[ETH_ALEN]; /* Ethernet destination address. */
  struct in_addr ip_src;     /* IP source address. */
  struct in_addr ip_dst;     /* IP destination address. */
  uint16_t tp_src;           /* TCP/UDP source port. */
  uint16_t tp_dst;           /* TCP/UDP destination port. */
  char in_port[IF_NAMSIZ];   /* Input port name */
  char out_port[IF_NAMSIZ];  /* Output port name */
};
#endif /* __FLOWID_H__ */
