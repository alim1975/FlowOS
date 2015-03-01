/**
 * AUTHOR: Abdul Alim <a.alim@lancaster.ac.uk>
 * FlowOS -- A flow processing platform.
 * Copyright (c) 2011 M. Abdul Alim, Lancaster University 
 */

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <net/ip.h>

#include "utils.h"
#include "pqueue.h"
#include "streamp.h"
#include "pmodule.h"
#include "pipeline.h"
#include "cmdline.h"
#include "messageq.h"
#include "protocol.h"
#include "mtcp.h"
#include "http.h"
#include "flowos.h"

/* the FlowOS data structure */
struct flowos flowos;

extern int txhandler_dispatch_stream(struct streamp *stp);

inline void flowos_drop_packet(void) {
  flowos.pktdropped++;
}

struct rxdev *is_rx_handler_registered(struct net_device *dev) {
  struct rxdev *ptr;
  TAILQ_FOREACH (ptr, &flowos.rxdev_list, list) {
    if (ptr->dev == dev) return ptr;
  }
  return NULL;
}

int flowos_add_rxdev(struct flow *flow) {
  struct flow *tmp;
  struct rxdev *rxd;
  struct flowdev *fdev;
  struct rte_eth_dev *dev;

  if (flow == NULL) return -1;
  dev = rte_eth_dev_get_by_name(flow->id.in_port);
  if (! dev) {
    printf("add_rxdev() : failed to find device %s\n", flow->id.in_port);
    return -1;
  }
  /* check if rxdev is already registered for flow->id->in_port */
  rxd = is_rx_handler_registered(dev);
  /* if not, register rxdev */
  if (rxd == NULL) {
    rxd = rte_malloc("rxdev", sizeof(*rxd), 0);
    if (! rxd) {
      print("add_rxdev(): failed to allocate rxd\n");
      return -1;
    }
    rxd->dev = dev;
    TAILQ_INIT(&rxd->flows);
    TAILQ_INSERT_TAIL(rxd, &flowos.rxdev_list, list);
  }
  /* make sure flow is not in the list before adding */
  
  TAILQ_FOREACH (tmp, &rxd->flows, list) {
    if (tmp == flow) {
      return 0;
    }
  }
  /* add flow to rxdev list */
  fdev = rte_malloc("flowdev", sizeof(struct flowdev), 0);
  if (! fdev) {
    printf("add_rxdev(): failed to allocate fdev\n");
    return -1;
  }
  fdev->flow = flow;
  TAILQ_INSERT_TAIL(fdev, &rxd->flows, list);

  return 0;
}

void flowos_del_rxdev(struct flow *flow) {
  struct rxdev *rxd, *tmp;
  struct flowdev *ptr, *temp;
  int deleted = 0; 
  if (flow == NULL) return;
  TAILQ_FOREACH_SAFE (rxd, &flowos.rxdev_list, list, tmp) {
    if (rxd->dev == rte_eth_dev_get_by_name(flow->id.in_port)) {
      TAILQ_FOREACH_SAFE (ptr, &rxd->flows, list, temp) {
	if (ptr->flow == flow) {
	  TAILQ_REMOVE(&rxd->flows, ptr, list);
	  rte_free(ptr);
	  deleted = 1;
	  break;
	}
      }
      if (deleted && TAILQ_EMPTY(&rxd->flows)) {
	TAILQ_REMOVE (&flowos.rxdev_list, rxd, list);
	rte_free(rxd);
	break;
      }
    }
  }    
}

/* register RX handler */
/* void flowos_register_rx_handler(struct net_device *dev,  rx_handler_fn rx_handler) { */
/*   rtnl_lock(); */
/*   netdev_rx_handler_unregister(dev); */
/*   netdev_rx_handler_register(dev, rx_handler, 0); */
/*   rtnl_unlock();     */
/* } */

/* void flowos_unregister_rx_handler(struct net_device *dev) */
/* { */
/*   rtnl_lock(); */
/*   netdev_rx_handler_unregister(dev); */
/*   rtnl_unlock(); */
/* } */

/* search for a given protocol decoder in the list of 
   registered decoders */
decoder_fn flowos_find_decoder(char *proto) {
  struct decoder *ptr;
  TAILQ_FOREACH(ptr, &flowos.decoder_list, list){
    if(strcasecmp(ptr->protocol, proto) == 0)
      return ptr->decoder;
  }
  return NULL;
}

inline flow_list_t *flowos_flow_list(void) {
  return &flowos.flow_list;
}

/* Find the flow the packet belongs to 
   FIXME: use IPTABLES APIs instead?? */
static struct flow *flowos_classify_skb(struct rte_mbuf *mbuf) {
  struct flow *flow;
  struct ethhdr *mach;
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  //  struct in_addr saddr;
  uint16_t fields;

  fields = 0;
  /* FIXME: very naive linear search, 
   * do some smart matching */
  TAILQ_FOREACH (flow, &flowos.flow_list, list) {   
    /* input port USE ID */
    if (flow->id.fields && FLOWOS_IN_PORT) {
      if (strcmp(mbuf->name, flow->id.in_port)) continue;
      fields |= FLOWOS_IN_PORT;
    }
        
    /* MAC source and destination addresses */
    if ((flow->id.fields & FLOWOS_MAC_SRC) || 
       (flow->id.fields & FLOWOS_MAC_DST)) {
      /* MAC header */
      mach = eth_hdr(mbuf);
      if (!mach) continue;
      /* MAC source address */
      if (flow->id.fields & FLOWOS_MAC_SRC) {
	if (strncmp(flow->id.mac_src, 
		   mach->h_source, 
		   ETH_ALEN) != 0)
	  continue;
	fields |= FLOWOS_MAC_SRC; 
      }
      /* MAC destination address */
      if(flow->id.fields & FLOWOS_MAC_DST){
	if(strncmp(flow->id.mac_dst, 
		   mach->h_dest, 
		   ETH_ALEN) != 0)
	  continue;
	fields |= FLOWOS_MAC_DST;
      }
    }
    /* IP header always exists */
    iph = (struct iphdr *)mbuf_network_header(mbuf);

    /* IP source address and destination address */
    if ((flow->id.fields & FLOWOS_IPv4_SRC) || 
       (flow->id.fields & FLOWOS_IPv4_DST)) {
      /* IPv4 source address */
      if (flow->id.fields & FLOWOS_IPv4_SRC) {
	if (flow->id.ip_src.s_addr != iph->saddr) continue;	
	else fields |= FLOWOS_IPv4_SRC;	
      }
      /* IPv4 destination address */
      if (flow->id.fields & FLOWOS_IPv4_DST) {
	if (flow->id.ip_dst.s_addr != iph->daddr) continue;
	fields |= FLOWOS_IPv4_DST;
      }
    }    
    /* TCP source and destination ports */
    if ((flow->id.fields & FLOWOS_TCP_SRC) || 
       (flow->id.fields & FLOWOS_TCP_DST)) {
      if (iph->protocol == IPPROTO_TCP)
	tcph = (struct tcphdr *) ((char *)iph + (iph->ihl << 2)); 
      else continue;
      /* TCP source port */
      if (flow->id.fields & FLOWOS_TCP_SRC) {
	if (flow->id.tp_src != tcph->source) continue;
	fields |= FLOWOS_TCP_SRC;
      }
      /* TCP destination port */
      if (flow->id.fields & FLOWOS_TCP_DST) {
	if (flow->id.tp_dst != tcph->dest) continue;
	fields |= FLOWOS_TCP_DST;
      }
    }
    /* UDP source and destination ports */
    if ((flow->id.fields & FLOWOS_UDP_SRC) || 
       (flow->id.fields & FLOWOS_UDP_DST)) {
      if (iph->protocol == IPPROTO_UDP)
	udph = (struct udphdr *) ((u_char *)iph + (iph->ihl << 2)); 
      else continue;
      /* UDP source port */
      if (flow->id.fields & FLOWOS_UDP_SRC) {
	if (flow->id.tp_src != udph->source) continue;
	fields |= FLOWOS_UDP_SRC;
      }
      /* UDP destination port */
      if (flow->id.fields & FLOWOS_UDP_DST) {
	if (flow->id.tp_dst != udph->dest) continue;
	fields |= FLOWOS_UDP_DST;
      }
    }
    /* we have found the flow */
    if (fields == flow->id.fields) return flow;
  }  
  /* No match found */
  return NULL;
}

/* decode sk_buff and create a packet for the flow */
struct packet *flowos_decode_mbuf(struct rte_mbuf *mbuf, struct flow *flow) {
  int i; 
  char *prev; 
  decoder_fn decoder; 
  struct packet *packet;
  struct tcphdr *th;
  struct udphdr *uh;
  struct iphdr *ih = ip_hdr(mbuf);

  if (! rte_pktmbuf_is_contiguous(mbuf)) {
    //if (rte_pktmbuf_linearize(mbuf) != 0) {
        printf("flowos_decode_skb(): does not handle non-linear packets\n");
	return NULL;
    }
  }	
  packet = packet_create(mbuf, flow->num_protos + 1);
  if (! packet) {
    printf("flowos_decode_mbuf(): failed to allocate packet\n");
    return NULL;
  }
  prev = NULL;
  for (i = 0; i < flow->num_protos; i++) {
    decoder = flowos_find_decoder(flow->protocols[i]);
    if (! decoder) {
      printf("FlowOS: Protocol %s decoder not found\n", flow->protocols[i]);
      packet_delete(packet);
      return NULL;
    }
    packet->parray[i] = decoder(mbuf, prev);
    prev = packet->parray[i];
  }
  /* pointer to the last byte of the packet */
  packet->parray[flow->num_protos] = (char *)ih + ntohs(ih->tot_len);  

  if (ih->protocol == IPPROTO_TCP) {
    th = (struct tcphdr *)((u8 *)ih + (ih->ihl << 2));
    packet->tseq = ntohl(th->seq);
    packet->tack = ntohl(th->ack_seq);
    packet->tlen = ntohs(ih->tot_len) - (ih->ihl << 2) - (th->doff << 2);
  }
  else if (ih->protocol == IPPROTO_UDP) {
    uh = (struct udphdr *)((u8 *)ih + (ih->ihl << 2));
    packet->tlen = ntohs(uh->len) - 8; //excluding header
  }
  return packet;
}

struct flow *flowos_peer_flow(struct flow *flow) {
  uint32_t fx, fy;
  struct flow *peer;
  fx = 0;
  fy = 0;
  TAILQ_FOREACH(peer, &flowos.flow_list, list){
    if(flow->id.fields & FLOWOS_IPv4_SRC){
      fx |= FLOWOS_IPv4_SRC;
      if(flow->id.ip_src.s_addr != peer->id.ip_dst.s_addr)
	continue;
      fy |= FLOWOS_IPv4_SRC;
    }
    if(flow->id.fields & FLOWOS_IPv4_DST){
      fx |= FLOWOS_IPv4_DST;
      if(flow->id.ip_dst.s_addr != peer->id.ip_src.s_addr)
	continue;
      fy |= FLOWOS_IPv4_DST;
    }
    if(flow->id.fields & FLOWOS_TCP_SRC){
      fx |= FLOWOS_TCP_SRC;
      if(flow->id.tp_src != peer->id.tp_dst)
	continue;
      fy |= FLOWOS_TCP_SRC;
    }
    if(flow->id.fields & FLOWOS_TCP_DST){
      fx |= FLOWOS_TCP_DST;
      if(flow->id.tp_dst != peer->id.tp_src)
        continue;
      fy |= FLOWOS_TCP_DST;
    }
    if(fx != 0 && fx == fy)
      return peer;
  }
  return NULL;
}
/*
int chk_ip_rcv(struct rte_mbuf *mbuf) {
    int len;
    struct iphdr *ih;
    struct rte_et_dev *dev = mbuf->dev;
    
    if(mbuf->pkt_type == PACKET_OTHERHOST) goto drop;

    if((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) goto out;
    }
    
    if(! pskb_may_pull(skb, sizeof(struct iphdr)))
      goto inhdr_error;
	
    ih = ip_hdr(skb);
    if(ih->ihl < 5 || ih->version != 4)
      goto inhdr_error;
    
    if(! pskb_may_pull(skb, ih->ihl << 2))
      goto inhdr_error;
      
    ih = ip_hdr(skb);
    if(unlikely(ip_fast_csum((u8 *)ih, ih->ihl)))
      goto inhdr_error; //csum_error;
      
    len = ntohs(ih->tot_len);
    if(skb->len < len){
      IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
      goto drop;
    }
    else if(len < (ih->ihl << 2))
      goto inhdr_error;
      
    if(pskb_trim_rcsum(skb, len)){
      IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
      goto drop;
    }
    skb->transport_header = skb->network_header + (ih->ihl << 2);
    memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    skb_orphan(skb);
    return 0;
    
//    csum_error:
//      IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_CSUMERRORS);
    inhdr_error:
      IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
    drop:
      kfree_skb(skb);
    out:
      return NET_RX_DROP;    
}
*/

int flowos_rx_handler(struct rte_mbuf *mbuf) {
  int ret;
  struct flow *flow;
  struct packet *packet;
  //  struct iphdr *ih;
  //  struct udphdr *uh;
  //  if(__get_cpu_var(unreceivable_sk_buff) == mbuf)
  //    return RX_HANDLER_PASS; /* This packet is being passed to kernel. */ 
  if (ntohs(rte_eth_hdr(mbuf)->h_proto) != ETH_P_IP) {
    return -1; /* Not an IP packet, pass it to the kernel  */
  }
  /* Is it a FlowOS control packet? */
  /* ih = ip_hdr(*mbuf); */
  /* if(ip_dev_find(sock_net((*mbuf)->sk), ih->daddr)){ */
  /*   if(ih->protocol == IPPROTO_UDP){ */
  /*     uh = (struct udphdr *) ((u_char *)ih + (ih->ihl << 2)); */
  /*     if(uh->dest == __constant_htons(UDP_ENCAP_PORT)){ */
  /* 	return RX_HANDLER_PASS; /\* FlowOS control packet, pass it to UDP encap server *\/ */
  /*     } */
  /*   } */
  /* }   */
  if (is_flow_table_empty()) {
    return -1; /* No flow, pass it to the kernel */
  }
  /* Borrowed from ip_rcv() */
  if (chk_ip_rcv(*mbuf) != 0) {
    //packet dropped...
    return -1;
  }
  /* find the flow the packet belongs to */
  flow = flowos_classify_mbuf(mbuf);
  if(! flow){
    return -1; /* No matching flow, pass it to the kernel */
  }
  /* DROP packets IF queue is FULL, TODO: use atomic */
  if (flow->size >= flow->capacity) {
    printf("FlowOS: packet queue is full, dropping...\n");
    flowos_drop_packet();
    return -1;
  }
  /* decode the packet */
  packet = flowos_decode_mbuf(mbuf, flow);
  if (! packet) {
    printf("FlowOS: ERROR failed to decode packet, dropping\n");
    flowos_drop_packet();
    return -1;
  }
  if (is_tcp_flow(flow)) { /* TCP connection management */
    ret = mtcp_input(flow, packet);
    if (ret != 0) { /* drop packet */
      printf("FlowOS: TCP input error, dropping packet...\n");
      flowos_drop_packet();
      packet_delete(packet);
      return -1;
    }
  }
  else { /* dispatch packet */
    flow_append_packet(flow, packet); //uses lock
  }
  return 0;
}

void flowos_dispatch_packet(struct flow *flow, struct packet *pkt) {
  int rc;
  struct iphdr *ih;
  struct rte_eth_dev *dev;
  if (flow == NULL || pkt == NULL || pkt->mbuf == NULL) {
    printf("flowos_dispatch_packet(): pkt is NULL\n");
    return;
  }
  flowos.pktprocessed++;
  ih = (struct iphdr *) packet_ip_header(pkt);
  //printf("flowos_dispatch_packet(): sending packet from %pI4 to %pI4\n", 
  //  &ih->saddr, &ih->daddr);
  if (rte_ip_dev_find(ih->daddr)) {
    print("dispatch_packet(): dispatching to application...\n");
    packet_delete(pkt); 
  }
  else {
    if (is_tcp_flow(flow) && flow->tcb_out != NULL) {
      //printf("disp_pkt(): TCP xmit packet...\n");
      /* output TCP connection for this flow */
      mtcp_xmit_packet(flow->tcb_out, pkt);
    }
    else {
      rc = flowos_xmit_mbuf(flow, pkt->mbuf);
      if (rc != 0) {
	printf("flowos_dispatch_packet(): failed to xmit packet %u\n", pkt->seq);
      }
      packet_delete(pkt);
    }
  }
}

/* Push data to the next PM: if it is the last PM 
   Pass data to the system */
void flowos_release_data(struct pmodule *src, struct streamp *tail) {
  struct pmodule *dst;  
  struct streamp *top = NULL;
  /* move current PM's head to the tail */
  top = pm_move_head(src, tail);
  /* if new top head pointer > my old head 
     UPDATE next stage PM's TAIL pointer get a copy of the top STREAMP  */
  if (pm_is_last_stage(src)) {
    //spin_lock(&srcpm->flow->head_lock);
    //if(SEQ_GT(top->packet->seq, srcpm->flow->head->seq)){
      txhandler_dispatch_stream(top); //uses lock
    //}
    //spin_unlock(&srcpm->flow->head_lock);
  }
  else {
    TAILQ_FOREACH (dst, next_stage_pms(src), list) {
      pthread_mutex_lock(&dst->tail_lock);
      streamp_map(&dst->tail, top); /* update dest PM's TAIL pointer */
      pthread_mutex_unlock(&dst->tail_lock);
      if (! dst->thread->running)
        pthread_cond_signal(&dst->thread->condition); /* notify the PM */
    }
  }
}

/* release a single BUFFERnode to next PM / to system */
void flowos_release_packet(struct pmodule *pm, struct packet *packet) {  
  struct iphdr *ih;
  struct pmodule *dst; 
  struct streamp *top;
  /* sanity check */
  if (pm == NULL || packet == NULL || packet->next == NULL) {
    printf("FlowOS: release_packet(NULL) error\n");
    return;
  }  
  pthread_mutex_lock(&pm->head_lock);
  /* move current PM's head next to the node */
  top = pm_set_head(pm, packet->next);
  //printf("release_packet(): "
  //    " (pkt->seq %u, pkt->next->seq %u)\n", packet->seq, packet->next->seq);
  /* if new top head pointer > old head UPDATE next-stage PM's TAIL pointer */
  if (SEQ_GT(packet->seq, top->packet->seq) || 
     (packet->seq == top->packet->seq)) { 
    //printf("release_packet(): nothing to release"
    //    " (pkt->seq %u, top->seq %u)\n", packet->seq, top->packet->seq);
    pthread_mutex_unlock(&pm->head_lock);
    return;
  }
  ih = packet_ip_header(packet);
  pthread_mutex_unlock(&pm->head_lock);
  /* NOTE: if there are multiple unsent packets, send them all */
  if(pm_is_last_stage(pm)){
    //printf("release() stp->flow %s stp->pkt %u to %pI4\n",
    //  top->flow->name, top->packet->seq, &ih->daddr);
    //pthread_mutex_lock(&pm->flow->head_lock);
    //if (SEQ_GT(top->packet->seq, pm->flow->head->seq)) {
      txhandler_dispatch_stream(top);
    //}
    //pthread_mutex_unlock(&pm->flow->head_lock);
  }
  else {
    TAILQ_FOREACH (dst, next_stage_pms(pm), list) {
      /* update dest PM's TAIL pointer */ 
      pthread_mutex_lock(&dst->tail_lock);
      streamp_set_packet(&dst->tail, packet->next);
      pthread_mutex_unlock(&dst->tail_lock);
      /* make sure PM's tail is updated */
      /* notify the PM */
      if (! dst->thread->runnung)
        pthread_cond_signal(&dst->thread->condition);
    }
  }
}

void flowos_get_flows(char *buff) {
  int count;  
  struct flow *flow;  
  count = 0;
  if (TAILQ_EMPTY(&flowos.flow_list))
    sprintf(buff, "FlowOS: Flow table is empty.");
  else {    
    TAILQ_FOREACH (flow, &flowos.flow_list, list) {
      count++;
    }
    if (count == 1)
      sprintf(buff, "FlowOS: 1 flow: ");
    else
      sprintf(buff, "FlowOS: %d flows: ", count);
    
    TAILQ_FOREACH(flow, &flowos.flow_list, list){
      strcat(buff, flow->name);
      strcat(buff, ", ");
    }
    if (buff[strlen(buff) - 2] == ',')
      buff[strlen(buff) - 2] = '\0';
  }
}

struct task *flowos_find_task(char *name) {
  struct pmodule *pm;
  TAILQ_FOREACH(pm, &flowos.module_list, list){
    if (strcmp(pm->task->name, name) == 0)
      return pm->task;
  }
  return NULL;
}

void flowos_save_task(struct task *task) {
  struct pmodule *pm;
  pm = rte_malloc("pmodule", sizeof(*pm), 0);
  pm->task = task;
  TAILQ_INSERT_TAIL(pm, &flowos.module_list, list);  
}

int flowos_remove_task(char *name) {
  struct pmodule *pm, *tmp;
  TAILQ_FOREACH_SAFE (pm, &flowos.module_list, list, tmp) {
    if (strcmp(pm->task->name, name) == 0) {
      TAILQ_REMOVE(&flowos.module_list, pm, list);
      rte_free(pm);
      return 0;
    }
  }
  return -1;
}

void flowos_get_pms(char *buff) {
  int count;
  struct pmodule *pm;
  count = 0;
  if (TAILQ_EMPTY(&flowos.module_list))
    sprintf(buff, "FlowOS: no PM is running.");
  else {
    TAILQ_FOREACH(pm, &flowos.module_list, list){
      count++;
    }
    if (count == 1) sprintf(buff, "FlowOS: 1 PM: ");
    else sprintf(buff, "FlowOS: %d PMs: ", count);

    TAILQ_FOREACH(pm, &flowos.module_list, list){
      strcat(buff, mod->task->name);
      strcat(buff, ", ");
    }
    if(buff[strlen(buff) - 2] == ',')
      buff[strlen(buff) - 2] = '\0';
  }
}

inline unsigned long flowos_get_pktprocessed(void) {
  return flowos.pktprocessed;
}

unsigned long flowos_get_pktdropped(void) {
  return flowos.pktdropped;
}

inline int is_flow_table_empty(void) {
  return TAILQ_EMPTY(&flowos.flow_list);
}

inline void flowos_save_flow(struct flow *flow) {
  list_add(&flow->list, &flowos.flow_list);
}

/* Lookup a flow by name in the flow list */
struct flow *flowos_find_flow(char *fname) {
  struct flow *flow;
  if (fname == NULL) return NULL;
  if (TAILQ_EMPTY(&flowos.flow_list)) return NULL;
  
  TAILQ_FOREACH (flow, &flowos.flow_list, list) {
    if (strcmp(flow->name, fname) == 0) return flow;
  }
  return NULL;
}

/* Remove a flow by name */
int flowos_remove_flow(char *fname) {
  struct flow *flow, *tmp;
  if (TAILQ_EMPTY(&flowos.flow_list)) {
    printf("FlowOS: flow list is empty\n");
    return 0;
  }
  TAILQ_FOREACH_SAFE (flow, &flowos.flow_list, list, tmp) {
    if (strcmp(fname, flow->name) == 0) { 
      TAILQ_REMOVE(&flowos.flow_list, flow, list);
      flow_delete(flow);
      return 0;
    }
  }
  printf("FlowOS: flow [%s] not found\n", fname);  
  return -1;
}

/* /\* kmod lookup by name *\/ */
/* struct kmod *flowos_find_kmod(const char *modname) */
/* { */
/*   struct kmod *kmod; */

/*   if(list_empty(&flowos.module_list)) */
/*     return NULL; */

/*   list_for_each_entry(kmod, &flowos.module_list, list){ */
/*     if(strcmp(kmod->mod->name, modname) == 0) */
/*       return kmod;     */
/*   } */
  
/*   return NULL; */
/* } */

/* void flowos_remove_kmod(struct kmod *kmod) */
/* { */
/*   struct list_head *ptr, *ptrnext; */
/*   struct kmod *temp; */

/*   list_for_each_safe(ptr, ptrnext, &flowos.module_list){ */
/*     temp = list_entry(ptr, struct kmod, list); */
/*     if(temp == kmod){ */
/*       list_del(ptr); */
/*       break; */
/*     } */
/*   } */
/* } */

/* Initialize the system */
int flowos_init(void) {
  printf("FlowOS: initializing...\n");
  /* # of packets processed */
  flowos.pktprocessed = 0;
  /* # of packets dropped */
  flowos.pktdropped = 0;
  /* list of flows */
  TAILQ_INIT(&flowos.flow_list);  
  /* list of processing modules */
  TAILQ_INIT(&flowos.module_list);
  TAILQ_INIT(&flowos.rxdev_list);
  /* list of protocol decoders */
  TAILQ_INIT(&flowos.decoder_list);  
  register_decoder(&flowos.decoder_list, ipv4_decoder, "ip");
  register_decoder(&flowos.decoder_list, tcp_decoder,  "tcp");
  register_decoder(&flowos.decoder_list, udp_decoder,  "udp");
  register_decoder(&flowos.decoder_list, http_decoder, "http");

  /* Initialize packet cache */
  if (packet_cache_init() != 0) {
    printF("FlowOS: failed to initialize packet cache\n");
    return -1;
  }
  /* Initialize streamp cache */
  if (streamp_cache_init() != 0) {
    printF("FlowOS: failed to initialize streamp cache\n");
    return -1;
  }
  /* Initialize message cache */
  if (msgqueue_cache_init() != 0) {
    printF("FlowOS: failed to initialize message cache\n");
    return -1;
  }
  /* FlowOS TX handler */
  if (txhandler_init() != 0) {
    printF("FlowOS: Failed to initialize TX handler\n");
    return -1;
  }
  printf("FlowOS: initialized TX handler\n");
  /* FlowOS UDP ENCAP */
  if (udp_encap_init() != 0) {
    printf("FlowOS: UDP encapsulation init failed\n");
    return -1;
  }
  printf("FlowOS: initialized UDP encap socket\n");
  /* Initialize TCP connection manager */
  if (mtcp_init() != 0) {
    printf("FlowOS: failed to initialize TCP connection manager\n");
    return -1;
  }
  printf("FlowOS: initialized TCP connection manager\n");
  /* Initialize NETLINK command interface */
  if (cmdline_init() != 0) {
    printf("FlowOS: Failed to initialize CLI\n");
    return -1;
  }
  printf("FlowOS: initialized NetLink CLI\n");

  return 0;
}

/* module cleanup procedure */
void flowos_stop(void) {
  struct flow *flow, *tmp;
  printf("FlowOS: exiting...\n");
  /* close UDP encapsulation */
  udp_encap_close();
  /* stop TX handler */
  txhandler_close();
  /* Remove command-line interface */
  cmdline_close();
  /* destroy message cache */
  msgqueue_cache_delete();
  // No flow is defined
  if (! TAILQ_EMPTY(&flowos.flow_list)) {
    // Delete all the flows 
    TAILQ_FOREACH_SAFE (flow, &flowos.flow_list, list, tmp) {
      TAILQ_REMOVE(flow);
      flow_delete(flow); 
    }
  }
  /* destroy packet cache */
  packet_cache_delete();
  /* destroy streamp cache */
  streamp_cache_delete();
  /* destroy TCP connection manager */
  mtcp_exit();
}


