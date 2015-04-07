#ifndef __ARP__
#define __ARP__

#define MAX_ARPENTRY 128

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

int flowos_init_arp_table();

unsigned char * get_mac_address(uint32_t ip);

unsigned char *get_dest_mac_address(uint32_t dip);

void flowos_send_request_arp(uint32_t ip, int nif, uint32_t cur_ts);

int flowos_process_arp_packet(uint32_t cur_ts, const int idx, struct rte_mbuf* pkt);

void flowos_publish_arp();

void flowos_print_arp_table();

#endif /* __ARP__ */
