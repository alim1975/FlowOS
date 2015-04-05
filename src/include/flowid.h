#ifndef __FLOWID_H__
#define __FLOWID_H__

#include <stdint.h>
#include <netinet/in.h>

/* IPv4 source address */
#define FLOWOS_IPv4_SRC 0x01
/* IPv4 destination address */
#define FLOWOS_IPv4_DST 0x02
/* TCP source port */
#define FLOWOS_TCP_SRC 0x04
/* TCP destination port */
#define FLOWOS_TCP_DST 0x08
/* UDP source port */
#define FLOWOS_UDP_SRC 0x10
/* UDP destination port */
#define FLOWOS_UDP_DST 0x20

/* Describe a flow using these fields */
struct flowid {
  uint16_t fields;           /* Wildcard fields */
  struct in_addr ip_src;     /* IP source address */
  struct in_addr ip_dst;     /* IP destination address */
  uint16_t tp_src;           /* TCP/UDP source port */
  uint16_t tp_dst;           /* TCP/UDP destination port */
};
typedef struct flowid* flowid_t;
#endif /* __FLOWID_H__ */
