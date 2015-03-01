#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>

#include "protocol.h"
#include "flow.h"
#include "pmodule.h"

extern struct list_head *flowos_flow_list(void);
extern void txhandler_dispatch_stream(struct streamp *);
extern int flowos_add_rxdev(struct flow *flow);
extern struct rxdev *is_rx_handler_registered(struct net_device *dev);
extern void flowos_del_rxdev(struct flow *flow);
extern void mtcp_shutdown_tcb(void *tcb);

/* Create a new flow */
struct flow *flow_create(struct flowid *id, char *fname)
{
  struct flow *flow; 
  struct net_device *idev;
  /* input port is not accessible/available */
  idev = dev_get_by_name(&init_net, id->in_port);
  if(! idev){
    printk(KERN_INFO "flow_create(): Unable to open input port [%s]\n", 
	   id->in_port);
    return NULL;
  }
  /* allocate a flow */
  flow = kmalloc(sizeof(*flow), GFP_KERNEL);
  if(! flow){
    printk(KERN_INFO "flow_create(): Unable to allocate memory\n");
    return NULL;
  }
  memcpy(&flow->id, id, sizeof(*id)); 
  flow->idev = idev;
  flow->rt = NULL;
  /* set flow name */
  strcpy(flow->name, fname);
  /* number of protocols to be parsed */
  flow->num_protos = 0;
  /* MAX queue size for flow */
  flow->capacity = MAX_FLOW_SIZE;
  /* current size */
  atomic_set(&flow->size, 0); 
  /* list of packet contains a dummy packet */
  flow->head = flow->tail = packet_create_dummy();
  //spin_lock_init(&flow->head_lock);
  spin_lock_init(&flow->tail_lock);  
  flow->pipeline = NULL;
  /* append the flow to the flow list */
  flowos_save_flow(flow);
  /* register RX handler */
  if(! is_rx_handler_registered(flow->idev))
    flowos_register_rx_handler(flow->idev, flowos_rx_handler);
  /* add flow to rxdev list */
  if(flowos_add_rxdev(flow) != 0){
    printk(KERN_INFO "FlowOS: error in adding tap dev to list\n");
  }
  return flow;
}

/* enqueue the packet to the tail */
void flow_append_packet(struct flow *flow, struct packet *pkt)
{
  int i;
  struct flowos_pm *pm;
  struct streamp stp;
  //printk(KERN_DEBUG "flow_append_packet(): adding packet to flow tail.\n");
  spin_lock_bh(&flow->tail_lock);
  flow->tail->skb = pkt->skb;
  flow->tail->levels = pkt->levels;
  for(i = 0; i < MAX_LEVELS; i++)
    flow->tail->parray[i] = pkt->parray[i];
  flow->tail->tseq = pkt->tseq;
  flow->tail->tack = pkt->tack;
  flow->tail->tlen = pkt->tlen;
  flow->tail->tsval = pkt->tsval;
  pkt->seq = flow->tail->seq + 1;
  pkt->skb = NULL;
  pkt->levels = 0;
  pkt->prev = flow->tail;   
  flow->tail->next = pkt;
  flow->tail = flow->tail->next;
  spin_unlock_bh(&flow->tail_lock);  
  atomic_inc(&flow->size);

  if(flow->pipeline == NULL){      /* No PM to process the flow, send out */
    //printk(KERN_DEBUG "flow_append_packet(): pipeline is empty, dispatching packet to kernel.\n");
    streamp_init(&stp, flow, 0);   /* set level IP */
    streamp_set_packet(&stp, pkt); /* packet after added to the flow */
    txhandler_dispatch_stream(&stp); // uses lock
  }
  else{
    list_for_each_entry(pm, pipeline_get_pms(flow->pipeline, 0), list){
      //printk(KERN_DEBUG "flow_append_packet(): sending wakeup signal to PM %s\n", pm->kmod->name);
      spin_lock_bh(&pm->tail_lock);
      streamp_set_packet(&pm->tail, pkt); /* update PM's tail pointer */
      spin_unlock_bh(&pm->tail_lock);      
      //BUG_ON(pkt->seq <= pkt->prev->seq);      
      if(pm->thread->state != TASK_RUNNING) {
        wake_up_process(pm->thread);        /* notify the PM */
      }
    }
  }
}

/* dequeue packet from the flow and return its value */
struct packet *flow_remove_packet(struct flow *flow)
{
  struct packet *pkt;
  //  smp_mb();
  if(atomic_read(&flow->size) == 0){    
    printk(KERN_INFO "flow_remove_packet(): flow is empty\n");
    return NULL;
  }
  //spin_lock(&flow->head_lock);
  pkt = flow->head;  
  //smp_wmb();
  flow->head = flow->head->next;
  if(! is_tcp_flow(flow))
    atomic_dec(&flow->size);
  //spin_unlock(&flow->head_lock);  
 
  return pkt;
}

/* Remove a flow 
 * TODO: consider the inconsistency of existing packets 
 * in the flow...
 * Detach processing modules from the flow
 * Delete packets in the flow -- free packets list
 * Remove processing modules that are not used by other 
 * flows -- decrement pcount
 * Free procs list 
 */
void flow_delete(struct flow *flow)
{
  struct packet *packet;
  if (flow == NULL) return;
  /* remove flow from rxdev list */
  flowos_del_rxdev(flow);
  /* if flow list is empty for dev, unregister RX handler */
  if (! is_rx_handler_registered(flow->idev))
    flowos_unregister_rx_handler(flow->idev);
  /* Free packets -- 
   * FIXME: consider a packet is shared by several flows...
   * Assumption: packet 1-to-1 flow relation 
   */
  pipeline_delete(flow->pipeline);
  
  if (is_tcp_flow(flow) && flow->tcb_out != NULL) 
    mtcp_shutdown_tcb(flow->tcb_out);
  /* delete any remaining packets in the flow */  
    while (flow->head != flow->tail){
    printk(KERN_INFO "flow_delete(): flow is not empty\n");
     packet = flow->head;
     flow->head = flow->head->next;
     if (packet->skb) consume_skb(packet->skb);
     packet_delete(packet);
   }
    /* free the dummy node */
  if (flow->tail) packet_delete(flow->tail);
  kfree(flow);  
}

void flow_set_protocols(struct flow *flow, char *protos)
{
  u8 count;
  char *ptr, *temp;
  count = 0;
  temp = kstrdup(protos, GFP_ATOMIC);
  ptr = strsep(&temp, ":");
  while(ptr){
    flow->protocols[count++] = kstrdup(ptr, GFP_ATOMIC);
    ptr = strsep(&temp, ":");
  }
  flow->num_protos = count;
}

int is_tcp_flow(struct flow *flow)
{
  int i;
  for(i = 0; i < flow->num_protos; i++){
    if(strcasecmp(flow->protocols[i], "tcp") == 0)
      return 1;
  }
  return 0;
}

u8 flow_get_level(struct flow *flow, char *proto)
{
  u8 i;
  for(i = 0; i < flow->num_protos; i++)
    if(strcasecmp(flow->protocols[i], proto) == 0)
      return i;
  return 0xff;
}

/* Add a processing module to a flow */
int flow_attach_pm(struct flow *flow, struct module *kmod, u8 pos)
{
  char name[80];
  struct flowos_pm *pm;
  if(! flow || ! kmod){
    printk(KERN_INFO "flow_attach_pm(): NULL pinter error\n");
    return -1;
  }
  pm = pm_init(kmod, flow, pos);
  if(! pm){
    printk(KERN_INFO "flow_attach_pm(): Failed to initialize pm [%s]\n", 
	   kmod->name);
    return -1;
  }
  sprintf(name, "%s-%s", flow->name, kmod->name);
  /* put a ref to the module to indicate that it is being used */
  try_module_get(kmod); 
  pipeline_add_pm(flow->pipeline, pm, pos);
  /* create a thread of this module for this flow */
  pm->thread = kthread_create((thread_fn)pm->process, pm, name);
  return 0;
}

/* FIXME: remove PM, rebuild pipeline */
int flow_detach_pm(char *flowname, char *modname)
{
  int stage;
  struct flow *flow;
  struct module *kmod;
  struct flowos_pm *pm, *temp;
  /* Lookup flow table for the flow */
  flow = flowos_find_flow(flowname);
  if(! flow){
    printk(KERN_INFO "flow_detach_pm(): Flow [%s] does not exist...", 
	   flowname);
    return -1;
  }
  kmod = find_module(modname);
  if(! kmod){
    printk(KERN_INFO "flow_detach_pm(): PM [%s] does not exist...", modname);
    return -1;
  }
  for(stage = 0; stage < pipeline_get_stages(flow->pipeline); stage++){
    list_for_each_entry_safe(pm, temp, pipeline_get_pms(flow->pipeline, stage), list){
      if(pm->kmod == kmod){
	/* unlink the thread */
	list_del(&pm->list);
	/* decrement ref count */
	module_put(pm->kmod);
	if(module_refcount(pm->kmod) == 0){
	  flowos_remove_pm(pm->kmod->name);
	}
	//pm_lock_heap(pm);
	//pqueue_remove(pipeline_get_heap(flow->pipeline, stage), &pm->head);
	//pm_unlock_heap(pm);	
	pm_delete(pm);
	return 0;
      }
    }
  }
  return -1;
}

