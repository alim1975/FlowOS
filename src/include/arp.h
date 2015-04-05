#ifndef __ARP_H__
#define __ARP_H__

#define MAX_ARPENTRY 128

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

typedef struct flowos* flowos_t;

int flowos_init_arp_table();

unsigned char * get_mac_address(uint32_t ip);

unsigned char *get_dest_mac_address(uint32_t dip);

void flowos_send_request_arp(flowos_t flowos, uint32_t ip, int nif, uint32_t cur_ts);

int flowos_process_arp_packet(flowos_t flowos, uint32_t cur_ts,
			      const int ifidx, struct rte_mbuf* pkt);

void flowos_publish_arp(flowos_t flowos);

void flowos_print_arp_table();

#endif /* __ARP_H__ */
