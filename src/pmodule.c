/* Copyright (c) 2011 M. Abdul Alim, Lancaster University */

/* FlowOS APIs for managing flow processing modules */
#include <linux/kallsyms.h>

#include "utils.h"
#include "pqueue.h"
#include "pmodule.h"
#include "pipeline.h"
#include "flowos.h"

typedef int (*getattr_fn)(void);
typedef char *(*getname_fn)(void);
/* initialize a processing module */
static int pm_resolve_functions(struct flowos_pm *pm, char *modname)
{
  int i;
  char symname[80];
  unsigned long symaddr;
  getattr_fn get_value;
  getname_fn get_name;

  sprintf(symname, "%s_process", modname);
  symaddr = kallsyms_lookup_name(symname);
  if(symaddr)
    pm->process = (pm_main_fn)symaddr;
  else{
    printk(KERN_INFO "pm_init(): Could not locate: %s()", symname);
    return -1;
  }
  /* Set Protocol */
  sprintf(symname, "%s_protocol", modname);
  symaddr = kallsyms_lookup_name(symname);
  if(symaddr){
    get_name = (getname_fn)symaddr;
    strcpy(pm->protocol, get_name());
  }
  else{
    printk(KERN_INFO "pm_init(): Could not locate: %s()", symname);
    return -1;
  }
  /* Set PM type RONLY/ RDWR */  
  sprintf(symname, "%s_type", modname);
  symaddr = kallsyms_lookup_name(symname);
  if(symaddr){
    get_value = (getattr_fn)symaddr; 
    pm->type = get_value();
  }
  else{
    printk(KERN_INFO "pm_init(): Could not locate: %s()", symname);
    return -1;
  }
  /* Set message count */
  sprintf(symname, "%s_nummsg", modname);
  symaddr = kallsyms_lookup_name(symname);
  if(symaddr){
    get_value = (getattr_fn)symaddr;
    pm->msgcount = get_value();
  }
  else{
    printk(KERN_INFO "pm_init(): PM %s  does not define %s()\n",
	   modname, symname);
    pm->msgcount = 0;
    pm->msg_handlers = NULL;
  }
  /* Register PM message handlers */  
  if(pm->msgcount > 0){
    pm->msg_handlers = (flowos_pmmsg_handler *)				\
      kmalloc(sizeof(flowos_pmmsg_handler) * pm->msgcount, GFP_ATOMIC);
    if(pm->msg_handlers == NULL){
      printk(KERN_INFO "pm_init(): no memory for msg handlers\n");
      kfree(pm);
      return -1;
    }
    for(i = 0; i < pm->msgcount; i++){ 
      sprintf(symname, "%s_%d_msghandler", modname, i);
      symaddr = kallsyms_lookup_name(symname);
      if(symaddr){
	pm->msg_handlers[i] = (flowos_pmmsg_handler)symaddr;
      }
      else{ 
	printk(KERN_INFO "pm_init(): could not locate: %s()", symname);
	kfree(pm->msg_handlers);
	kfree(pm);
	return -1;
      }
    }
  }
  return 0;
}

/* make sure no one is using it then 
 * remove ref. from flows, unload the module, 
 * free associated memory
 */
struct flowos_pm *pm_init(struct module *kmod, struct flow *flow, u8 order)
{
  int ret;
  u8 level;
  struct flowos_pm *pm;
  /* create a new thread and insert it 
     at pos in the thread list of the flow */
  pm = kmalloc(sizeof *pm, GFP_ATOMIC);
  if(pm == NULL){
    printk(KERN_INFO "pm_init(): unable to initialize PM...\n ");
    return NULL;
  }
  ret = pm_resolve_functions(pm, kmod->name);
  if(ret != 0){
    kfree(pm);
    return NULL;
  }
  level = flow_get_level(flow, pm->protocol); 
  if(level == 0xff){
    printk(KERN_INFO "pm_init(): flow does not have [%s] stream\n", 
	   pm->protocol);
    kfree(pm);
    return NULL;
  }
  /* the flow to which this thread attached */
  pm->flow = flow;
  /* pointer to Module */ 
  pm->kmod = kmod; 
  /* insert this thread at specified position 
   * on the pipeline */
  pm->order = order;
  /* initialize message queue */
  if(pm->msgcount > 0){
    pm->mq = msgqueue_create();
    if(pm->mq == NULL){
      kfree(pm->msg_handlers);
      kfree(pm);
      printk(KERN_INFO "pm_init(): failed to create msg queue\n");
      return NULL;
    }
  }
  else pm->mq = NULL;
  /* initialize head and */
  streamp_init(&pm->head, flow, level);
  streamp_set_packet(&pm->head, flow->head);
  /* set PM tail pointer */
  streamp_init(&pm->tail, flow, level);
  streamp_set_packet(&pm->tail, flow->head);
  /* initialize head/tail locks */
  spin_lock_init(&pm->head_lock);
  spin_lock_init(&pm->tail_lock);

  return pm;
}

inline void pm_delete(struct flowos_pm *pm)
{
  /* stop kernel thread */  
  kthread_stop(pm->thread); 
  /* free msg queue */
  if(pm->mq){
    msgqueue_delete(pm->mq);
  }
  /* free PM */
  if(pm->msgcount > 0)
    kfree(pm->msg_handlers);
  kfree(pm);
}

/* check if data is available for this PM */
int pm_is_empty(struct flowos_pm *pm)
{
  if(pm->head.ptr == NULL || streamp_is_equal(&pm->head, &pm->tail))
    return 1;  
  else
    return  0;
}
EXPORT_SYMBOL(pm_is_empty);
    
/* Set PM's head to packet and return the least head pointer
 * of all concurrent PMs 
 */
struct streamp *pm_set_head(struct flowos_pm *pm, struct packet *packet)
{
  struct streamp *top;
  struct flowos_pm *ppm;
  struct pipeline *p = pm->flow->pipeline;
//  WARN_ON(pm->head.packet->seq > packet->seq);
  streamp_set_packet(&pm->head, packet);
  top = &pm->head;  
  if(p->stages == 1){
    return top;  
  }
//  pm_lock_heap(pm);
//  pqueue_update(pm_get_heap(pm), &pm->head);
//  top = pqueue_top(pm_get_heap(pm));
//  pm_unlock_heap(pm);
   list_for_each_entry(ppm, &p->pms[pm->order], list){
     if(streamp_compare(&ppm->head, top) < 0)
       top = &ppm->head;
   }
  return top;
}
EXPORT_SYMBOL(pm_set_head);

void pm_update_head(struct flowos_pm *pm)
{
  struct streamp temp, tail;
  if(pm->head.ptr == NULL){
    if(streamp_set_packet(&pm->head, pm->head.packet))
      return;
    temp = pm->head; 
    spin_lock_bh(&pm->tail_lock);
    tail = pm->tail;
    spin_unlock_bh(&pm->tail_lock);
    /* try to move head pointer. if head moves forward, release data */
    streamp_post_inc(&temp, &tail);
    if(SEQ_GT(temp.packet->seq, pm->head.packet->seq)){
      flowos_release_data(pm, &temp);
    }    
  }
}
EXPORT_SYMBOL(pm_update_head);

/* Move PM's head pointer to stp and return the least 
 * head pointer of all concurrent PMs 
 */
struct streamp *pm_move_head(struct flowos_pm *pm, struct streamp *stp)
{
  struct streamp *top;
  struct flowos_pm *ppm;
  struct pipeline *p = pm->flow->pipeline;

  WARN_ON(pm->head.packet->seq > stp->packet->seq);
  streamp_map(&pm->head, stp);
  top = &pm->head;
  if(p->stages == 1) return top;
  /* update the heap of head pointers */
  //pm_lock_heap(pm);
  //pqueue_update(pm_get_heap(pm), &pm->head); 
  //top = pqueue_top(pm_get_heap(pm));
  //pm_unlock_heap(pm);
  list_for_each_entry(ppm, &p->pms[pm->order], list){
    if(streamp_compare(&ppm->head, top) < 0)
      top = &ppm->head;  
  }
  return top;
}
EXPORT_SYMBOL(pm_move_head);

inline void pm_dispatch_message(struct flowos_pm *pm, 
				struct flowos_pmhdr *pmh)
{
  if(pm->mq == NULL){
    printk(KERN_INFO "pm_dispatch(): msg queue not initialized\n");
    return;
  }
  msgqueue_insert(pm->mq, (void *)pmh);
  //smp_wmb();
  if(pm->thread->state != TASK_RUNNING)
    wake_up_process(pm->thread);
}

void pm_process_message(struct flowos_pm *pm)
{
  int rc;
  char msg[80];
  struct flowos_pmhdr *req;
  if(pm->mq == NULL) return;
  while((req = (struct flowos_pmhdr *)msgqueue_remove(pm->mq))){
    rc = -1;
    if(req->command < pm->msgcount && pm->msg_handlers[req->command]){
      /* invoke actual message handler */
      rc = (*pm->msg_handlers[req->command])(pm, req); 
    }
    /* send ACK */
    if(rc < 0){
      sprintf(msg, "FlowOS: Failed to process PM message");
      printk(KERN_INFO "%s\n", msg);
      pm_send_response(req, FLOWOS_FAILURE, msg, strlen(msg));    
    }
    kfree(req);
  }  
}
EXPORT_SYMBOL(pm_process_message);

