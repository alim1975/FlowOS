#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>

#include <rte_mempool.h>
#include <rte_ether.h>

#include "protocol.h"
#include "flow.h"

static rte_mempool *flow_pool = NULL;
int flow_pool_init(uint32_t size) {
  flow_pool = rte_mempool_create("flow_pool", 
				 size,
				 sizeof(struct flow),
				 0, 0, 
				 NULL, NULL, NULL, NULL,
				 0, 0);
  if (! flow_pool) {
    printf("FlowoS failed to create flow pool.\n");
    return -1;
  }
  return 0;
}

/* Create a new flow */
flow_t flow_create(flowid_t id, char *name) {
  flow_t flow;
  if ( rte_mempool_get(flow_pool, &flow) != 0) {
    printf("flow_create() failed to create flow entry.\n");
    return NULL;
  }
  /* set flow name */
  strcpy(flow->name, name);
  memcpy(&flow->id, id, sizeof(*id)); 
  /* number of protocols to be parsed */
  flow->protocolCount = 0;
  /* MAX queue size for flow */
  flow->capacity = MAX_FLOW_SIZE;
  flow->pipeline = NULL;
  TAILQ_INIT(&flow->head);
  rte_spinlock_init(&flow->lock);
  /* append the flow to the flow list */
  flowos_insert_flow(&flowos.flow_list, flow);
  return flow;
}

/* enqueue the packet to the tail */
void flow_append_packet(flow_t flow, packet_t pkt) {
  task_t task;
  streamp_t stp;
  rte_spinlock_lock(&flow->lock);
  TAILQ_INSERT_BEFORE(&flow->head, pkt->list);
  flow->size++;
  rte_spinlock_unlock(&flow->lock);
  /* No PM to process the flow, send out */
  TAILQ_FOREACH(task, pipeline_get_pms(flow->pipeline, 0), list){
    channnel_insert(task->rxChannel, pkt); 
    if (task_is_runnable(task)) scheduler_submit(task);  
  }
}

/* dequeue packet from the flow and return its value */
packet_t flow_remove_packet(flow_t flow) {
  packet_t pkt;
  rte_spinlock_lock(&flow->lock);
  if (TAILQ_EMPTY(&flow-head)) {
    rte_spinlock_unlock(&flow->lock);
    print("flow_remove_packet(): flow is empty\n");
    return NULL;
  }
  rte_spinlock_lock(&flow->lock);
  pkt = TAILQ_REMOVE(&flow->head);
  rte_spinlock_unlock(&flow->lock);    
  return pkt;
}

/* Remove a flow */
void flow_delete(flow_t flow) {
  packet_t packet;
  assert(flow);
  /* Free packets -- 
   * FIXME: consider a packet is shared by several flows...
   * Assumption: packet 1-to-1 flow relation 
   */
  rte_spinlock_lock(&flow->lock);
  pipeline_delete(flow->pipeline);
  /* delete any remaining packets in the flow */  
  while (! TAILQ_EMPTY(&flow->head)) {
    printf("flow_delete(): flow is not empty\n");
    packet = TAILQ_REMOVE(&flow->head);
    packet_delete(packet);
  }
  rte_spinlock_unlock(&flow->lock);
  flowos_remove_flow(&flowos.flow_list, flow);
}

void flow_set_protocols(flow_t flow, char *protocols) {
  uint8_t count = 0;
  char *ptr, *temp;
  /* TODO: keep protocol IDs instead of names */
  temp = strdup(protocols);
  ptr = strsep(&temp, ":");
  while (ptr) {
    flow->protocols[count++] = strdup(ptr);
    ptr = strsep(&temp, ":");
  }
  flow->protocolCount = count;
}

int is_tcp_flow(flow_t flow) {
  int i;
  for (i = 0; i < flow->num_protos; i++) {
    if (strcasecmp(flow->protocols[i], "tcp") == 0)
      return 1;
  }
  return 0;
}

int8_t flow_get_levelflow_t flow, char *protocol) {
  int8_t i; 
  for (i = 0; i < flow->protocolCount; i++)
    if (strcasecmp(flow->protocols[i], protocol) == 0)
      return i;
  return -1; 
}

/* Add a processing task to a flow */
int flow_attach_task(flow_t flow, task_t task, uint8_t pos) {
  char name[80];
  task_t t;
  assert (flow && task);
  task_init(task, flow, pos);
  sprintf(name, "%s.%s", flow->name, task->name);
  pipeline_add_task(flow->pipeline, task, pos);
  return 0;
}

flow_t flowos_classify_packet(struct rte_mbuf *mbuf) {
  flow_t flow;
  struct ethhdr *mach;
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  uint16_t fields;

  fields = 0;
  /* FIXME: very naive linear search, 
   * do some smart matching */
  TAILQ_FOREACH (flow, &flowos.flow_list, list) {   
    /* IP header always exists */
    iph = (struct iphdr *)((struct ethhdr *) 
			   rte_pktmbuf_mtod(pkt, struct ethhdr*) + 1);
    /* IP source address and destination address */
    if ((flow->id.fields & FLOWOS_IPv4_SRC) || (flow->id.fields & FLOWOS_IPv4_DST)) {
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
    if ((flow->id.fields & FLOWOS_TCP_SRC) || (flow->id.fields & FLOWOS_TCP_DST)) {
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
    if ((flow->id.fields & FLOWOS_UDP_SRC) || (flow->id.fields & FLOWOS_UDP_DST)) {
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

/* decode network buffer and create a packet for the flow */
packet_t flowos_decode_mbuf(struct rte_mbuf *mbuf, flow_t flow) {
  int i; 
  char *prev; 
  decoder_fn decoder; 
  packet_t packet;
  struct tcphdr *th;
  struct udphdr *uh;
  struct iphdr *ih = (struct iphdr *)
    ((struct ethhdr *) rte_pktmbuf_mtod(pkt, struct ethhdr*) + 1);
  /* TODO: check buffer is not scattered */
  packet = packet_create(mbuf, flow->protocolCount + 1);
  if (! packet) {
    printf("flowos_decode_mbuf(): failed to allocate packet\n");
    return NULL;
  }
  prev = NULL;
  for (i = 0; i < flow->protocolCount; i++) {
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
