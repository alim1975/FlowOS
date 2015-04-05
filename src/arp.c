#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <rte_malloc.h>
#include <rte_ether.h>

#include "flowos.h"
#include "arp.h"
#include "eth_in.h"
#include "eth_out.h"

#define ARP_LEN 28
#define ARP_HEAD_LEN 8

/*--------------------------------------------------------------------*/
enum arp_hrd_format {
  arp_hrd_ethernet = 1
};
/*--------------------------------------------------------------------*/
enum arp_opcode {
  arp_op_request = 1, 
  arp_op_reply = 2, 
};
/*--------------------------------------------------------------------*/
struct arphdr {
  uint16_t ar_hrd;		/* hardware address format */
  uint16_t ar_pro;		/* protocol address format */
  uint8_t ar_hln;		/* hardware address length */
  uint8_t ar_pln;		/* protocol address length */
  uint16_t ar_op;		/* arp opcode */
  
  uint8_t ar_sha[ETH_ALEN];	/* sender hardware address */
  uint32_t ar_sip;		/* sender ip address */
  uint8_t ar_tha[ETH_ALEN];	/* targe hardware address */
  uint32_t ar_tip;		/* target ip address */
} __attribute__ ((packed));
/*--------------------------------------------------------------------*/
struct arp_queue_entry {
  uint32_t ip;
  int nif_out;
  uint32_t ts_out;

  TAILQ_ENTRY(arp_queue_entry) arp_link;
};
/*--------------------------------------------------------------------*/
struct arp_manager {
  TAILQ_HEAD (, arp_queue_entry) list;
  int cnt;
};
/*--------------------------------------------------------------------*/
static struct arp_manager arpm;
/*--------------------------------------------------------------------*/
void flowos_dump_arp_packet(struct arphdr *arph);
/*--------------------------------------------------------------------*/
int flowos_init_arp_table() {
  printf("FlowOS: initializing ARP table...\n");
  CONFIG.arp.entries = 0;

  CONFIG.arp.entry = (struct arp_entry *)
    rte_calloc("arp_entry", MAX_ARPENTRY, sizeof(struct arp_entry), 0);
  if (CONFIG.arp.entry == NULL) {
    perror("rte_calloc");
    return -1;
  }
  
  TAILQ_INIT(&arpm.list);
  
  return 0;
}
/*--------------------------------------------------------------------*/
unsigned char *flowos_get_mac_address(uint32_t ip) {
  int i;
  unsigned char *haddr = NULL;
  for (i = 0; i < CONFIG.eths_num; i++) {
    if (ip == CONFIG.eths[i].ip_addr) {
      haddr = CONFIG.eths[i].haddr;
      break;
    }
  }

  return haddr;
}
/*--------------------------------------------------------------------*/
unsigned char *flowos_get_dest_mac_address(uint32_t dip) {
  unsigned char *d_haddr = NULL;
  int prefix = 0;
  int i;
  
  /* Longest prefix matching */
  for (i = 0; i < CONFIG.arp.entries; i++) {
    if (CONFIG.arp.entry[i].prefix == 1) {
      if (CONFIG.arp.entry[i].ip == dip) {
	d_haddr = CONFIG.arp.entry[i].haddr;
	break;
      }	
    } 
    else {
      if ((dip & CONFIG.arp.entry[i].ip_mask) ==
	  CONFIG.arp.entry[i].ip_masked) {
	
	if (CONFIG.arp.entry[i].prefix > prefix) {
	  d_haddr = CONFIG.arp.entry[i].haddr;
	  prefix = CONFIG.arp.entry[i].prefix;
	}
      }
    }
  }
  
  return d_haddr;
}
/*--------------------------------------------------------------------*/
static int flowos_arp_output(flowos_t flowos, int nif, int opcode,
			     uint32_t dst_ip, unsigned char *dst_haddr) {
  if (! dst_haddr) return -1;

  /* Allocate a buffer */
  struct arphdr *arph = (struct arphdr *)
    flowos_eth_output(flowos, ETH_P_ARP, nif, dst_haddr, sizeof(struct arphdr));
  if (! arph) {
    printf("FlowOS: failed to get ethernet frame to send ARP reply\n");
    return -1;
  }
  /* Fill arp header */
  arph->ar_hrd = htons(arp_hrd_ethernet);
  arph->ar_pro = htons(ETH_P_IP);
  arph->ar_hln = ETH_ALEN;
  arph->ar_pln = 4;
  arph->ar_op = htons(opcode);
  
  /* Fill arp body */
  arph->ar_sip = CONFIG.eths[nif].ip_addr;
  arph->ar_tip = dst_ip;
  
  memcpy(arph->ar_sha, CONFIG.eths[nif].haddr, arph->ar_hln);
  memcpy(arph->ar_tha, dst_haddr, arph->ar_hln);
  
#if DBGMSG
  flowos_dump_arp_packet(arph);
#endif

  return 0;
}
/*--------------------------------------------------------------------*/
int flowos_register_arp_entry(uint32_t ip, const unsigned char *haddr) {
  int idx = CONFIG.arp.entries;
  
  CONFIG.arp.entry[idx].prefix = 32;
  CONFIG.arp.entry[idx].ip = ip;
  memcpy(CONFIG.arp.entry[idx].haddr, haddr, ETH_ALEN);
  CONFIG.arp.entry[idx].ip_mask = -1;
  CONFIG.arp.entry[idx].ip_masked = ip;
  
  CONFIG.arp.entries = idx + 1;

  printf("FlowOS: learned new ARP entry.\n");
  flowos_print_arp_table();
  
  return 0;
}
/*--------------------------------------------------------------------*/
void flowos_send_arp_request(flowos_t flowos, uint32_t ip, int nif, uint32_t cur_ts) {
  struct arp_queue_entry *ent;
  unsigned char haddr[ETH_ALEN];
  
  /* if the arp request is in progress, return */
  TAILQ_FOREACH(ent, &arpm.list, arp_link) {
    if (ent->ip == ip) return;
  }
  
  ent = (struct arp_queue_entry *) 
    rte_calloc("arp_queue_entry", 1, sizeof(struct arp_queue_entry), 0);
  ent->ip = ip;
  ent->nif_out = nif;
  ent->ts_out = cur_ts;
  TAILQ_INSERT_TAIL(&arpm.list, ent, arp_link);
  
  /* else, broadcast arp request */
  memset(haddr, 0xFF, ETH_ALEN);
  flowos_arp_output(flowos, nif, arp_op_request, ip, haddr);
}
/*-------------------------------------------------------------------*/
static int flowos_process_arp_request(flowos_t flowos, 
				      struct rte_mbuf *pkt,
				      int nif, 
				      uint32_t cur_ts) {
  unsigned char *temp;
  struct arphdr *arph = (struct arphdr *)
    (rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr));  
  /* register the arp entry if not exist */
  temp = flowos_get_dest_mac_address(arph->ar_sip);
  if (! temp) {
    //printf("Insert new ARP entry from request\n");
    flowos_register_arp_entry(arph->ar_sip, arph->ar_sha);
  }
  /* send ARP reply */
  flowos_arp_output(flowos, nif, arp_op_reply, arph->ar_sip, arph->ar_sha);
 
  rte_pktmbuf_free(pkt);
  return 0;
}
/*----------------------------------------------------------------------------*/
static int flowos_process_arp_reply(flowos_t flowos, 
				    struct rte_mbuf *pkt,
				    uint32_t cur_ts) {
  unsigned char *temp;
  struct arp_queue_entry *ent;
  struct arphdr *arph = (struct arphdr *)
    (rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr));
  /* register the arp entry if not exist */
  temp = flowos_get_dest_mac_address(arph->ar_sip);
  if (! temp) {
    //printf("Insert new ARP entry from reply\n");
    flowos_register_arp_entry(arph->ar_sip, arph->ar_sha);
  }
  /* remove from the arp request queue */
  TAILQ_FOREACH(ent, &arpm.list, arp_link) {
    if (ent->ip == arph->ar_tip) {
      TAILQ_REMOVE(&arpm.list, ent, arp_link);
      rte_free(ent);
      break;
    }
  }

  rte_pktmbuf_free(pkt);  
  return 0;
}
/*-------------------------------------------------------------------*/
int flowos_process_arp_packet(flowos_t flowos, uint32_t cur_ts,
			      const int ifidx, struct rte_mbuf *pkt) {
  struct arphdr *arph = (struct arphdr *)
    (rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr));

  int i;
  int to_me = FALSE;
  
  /* process the arp messages destined to me */
  for (i = 0; i < CONFIG.eths_num; i++) {
    if (arph->ar_tip == CONFIG.eths[i].ip_addr) {
      to_me = TRUE;
    }
  }
  
  if (! to_me) {
    printf("ARP packet for me...\n");
    rte_pktmbuf_free(pkt);
    return TRUE;
  }
#if DBGMSG
  flowos_dump_arp_packet(arph);
#endif

  switch (ntohs(arph->ar_op)) {
  case arp_op_request:
    flowos_process_arp_request(flowos, pkt, ifidx, cur_ts);
    break;
    
  case arp_op_reply:
    flowos_process_arp_reply(flowos, pkt, cur_ts);
    break;
    
  default:
    rte_pktmbuf_free(pkt);
    break;
  }
  
  return TRUE;
}
/*-------------------------------------------------------------------*/
// Publish my address
void flowos_advertise_mac_address(flowos_t flowos) {
  int i;
  for (i = 0; i < CONFIG.eths_num; i++) {
    flowos_arp_output(flowos, CONFIG.eths[i].ifindex, 
		      arp_op_request, 0, NULL);
  }
}
/*-------------------------------------------------------------------*/
void flowos_print_arp_table() {
  int i;  
  /* print out process start information */
  printf("FlowOS: ARP table\n");
  for (i = 0; i < CONFIG.arp.entries; i++) {
    uint8_t *da = (uint8_t *)&CONFIG.arp.entry[i].ip;
    
    printf("IP addr: %u.%u.%u.%u, "
		 "dst_mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
		 da[0], da[1], da[2], da[3],
		 CONFIG.arp.entry[i].haddr[0],
		 CONFIG.arp.entry[i].haddr[1],
		 CONFIG.arp.entry[i].haddr[2],
		 CONFIG.arp.entry[i].haddr[3],
		 CONFIG.arp.entry[i].haddr[4],
		 CONFIG.arp.entry[i].haddr[5]);
  }
  if (CONFIG.arp.entries == 0)
    printf("(blank)\n");
  
  printf("----------------------------------------------------------"
	 "-----------------------\n");
}
/*--------------------------------------------------------------------*/
void flowos_dump_arp_packet(struct arphdr *arph) {
  uint8_t *t;
  
  fprintf(stderr, "FloOoS: ARP header \n");
  fprintf(stderr, "Hareware type: %d (len: %d), "
	  "protocol type: %d (len: %d), opcode: %d\n", 
	  ntohs(arph->ar_hrd), arph->ar_hln, 
	  ntohs(arph->ar_pro), arph->ar_pln, ntohs(arph->ar_op));
  t = (uint8_t *)&arph->ar_sip;
  fprintf(stderr, "Sender IP: %u.%u.%u.%u, "
	  "haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
	  t[0], t[1], t[2], t[3], 
	  arph->ar_sha[0], arph->ar_sha[1], arph->ar_sha[2], 
	  arph->ar_sha[3], arph->ar_sha[4], arph->ar_sha[5]);
  t = (uint8_t *)&arph->ar_tip;
  fprintf(stderr, "Target IP: %u.%u.%u.%u, "
	  "haddr: %02X:%02X:%02X:%02X:%02X:%02X\n", 
	  t[0], t[1], t[2], t[3], 
	  arph->ar_tha[0], arph->ar_tha[1], arph->ar_tha[2], 
	  arph->ar_tha[3], arph->ar_tha[4], arph->ar_tha[5]);
}
/*-------------------------------------------------------------------*/
