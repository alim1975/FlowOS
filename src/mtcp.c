#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/route.h>

#include "khashtable.h"
#include "pqueue.h"
#include "flow.h"
#include "mtcp.h"

/** List of all TCBs that are in a state in which
 * they accept or send data. */
struct list_head mtcp_active_tcbs;
/** List of all TCBs in CLOSED state */
struct list_head mtcp_closed_tcbs;
/** Timer counter to handle calling slow-timer from mtcp_tmr() */ 
static struct timer_list mtcp_timer;
/** global variable that shows if the tcp timer is scheduled or not */
static int mtcp_timer_active;
/** global variable to control TCP timer */
uint32_t mtcp_ticks;

extern void flowos_drop_packet(void);

extern struct flow *flowos_peer_flow(struct flow *);

static void mtcp_timer_callback(unsigned long dummy);

struct tcb *mtcp_peer(struct tcb *);

inline static struct mtcp_key mtcp_getkey(struct packet *pkt)
{
  struct mtcp_key key;
  struct iphdr *ih = (struct iphdr *)packet_ip_header(pkt);
  struct tcphdr *th = (struct tcphdr *)packet_tcp_header(pkt);
  key.saddr = ih->saddr;
  key.daddr = ih->daddr; 
  key.sport = th->source;
  key.dport = th->dest;
  return key;
}

static void mtcp_timer_callback(unsigned long dummy)
{
  /* call TCP timer handler */
  mtcp_tmr();
  /* timer still needed? */
  if(! list_empty(&mtcp_active_tcbs) || ! list_empty(&mtcp_closed_tcbs)) {
    /* restart timer */
    mod_timer(&mtcp_timer, jiffies + msecs_to_jiffies(MTCP_TMR_INTERVAL));
  }
  else{
    /* disable timer */
    mtcp_timer_active = 0;
  }
}

void mtcp_timer_needed(void)
{
  /* timer is off but needed again? */
  if(! mtcp_timer_active && 
     (! list_empty(&mtcp_active_tcbs) || ! list_empty(&mtcp_closed_tcbs))) {
    /* enable and start timer */
    mtcp_timer_active = 1;
    mod_timer(&mtcp_timer, jiffies + msecs_to_jiffies(MTCP_TMR_INTERVAL));
  }
}

int mtcp_init(void)
{
  INIT_LIST_HEAD(&mtcp_active_tcbs);
  INIT_LIST_HEAD(&mtcp_closed_tcbs);
  setup_timer(&mtcp_timer, mtcp_timer_callback, 0);
  /* start timer */
  mtcp_timer_active = 1;
  mod_timer(&mtcp_timer, jiffies + msecs_to_jiffies(MTCP_TMR_INTERVAL));
  return 0;
}

void mtcp_exit(void)
{
  del_timer_sync(&mtcp_timer);
  /* TODO: take care of saved packets etc... */  
}

static struct tcb *mtcp_alloc(__be32 saddr, __be16 sport,
			      __be32 daddr, __be16 dport)
{
  struct tcb *tcb;
  tcb = kmalloc(sizeof(struct tcb), GFP_ATOMIC);
  if(! tcb){
    printk(KERN_INFO "mtcp_alloc(): failed to create TCP session...\n");
    return NULL;
  }
  INIT_LIST_HEAD(&tcb->unsent); 
  INIT_LIST_HEAD(&tcb->unacked);
  INIT_LIST_HEAD(&tcb->ooseq);
  INIT_LIST_HEAD(&tcb->sack_blocks);
  spin_lock_init(&tcb->lock);
  spin_lock_init(&tcb->rcv_nxt_lock);
  tcb->tos = 0; 
  tcb->ttl = MTCP_TTL;
  //  tcb->rto = 3000 / MTCP_SLOW_INTERVAL;
  tcb->sa = 0;
  tcb->sv = 3000 / MTCP_SLOW_INTERVAL;
  tcb->mss = (MTCP_MSS > 536) ? 536 : MTCP_MSS;
  tcb->rcv_wnd = MTCP_WND;
  tcb->rcv_wnd_max = MTCP_WND;
  tcb->rcv_wscale = 0;
  tcb->snd_wnd = MTCP_WND;
  tcb->snd_wscale = 0;
  tcb->lastack = 0;
  tcb->sack_ok = 0;
  tcb->sack_last_update = NULL;
  tcb->ts_enabled = 0;
  tcb->timer = tcb->rto = MTCP_RTO;
  tcb->prio = MTCP_PRIO_NORMAL;
  tcb->flags = 0;
  tcb->key.saddr = saddr;
  tcb->key.daddr = daddr;
  tcb->key.sport = sport;
  tcb->key.dport = dport; 
  return tcb;
}

int mtcp_create(struct flow *flow, struct packet *pkt)
{
  struct iphdr *ih;
  struct tcphdr *th;
  struct tcb *client, *server;
  struct flow *peer;
  ih = (struct iphdr *)packet_ip_header(pkt);
  th = (struct tcphdr *)packet_tcp_header(pkt);
  peer = flowos_peer_flow(flow);
  if(peer == NULL){
    printk(KERN_INFO "mtcp_new(): failed to locate peer flow\n");
    return -1;
  }
  //printk(KERN_DEBUG "mtcp_new(): creating TCP server proxy.\n");
  server = mtcp_alloc(ih->saddr, th->source, ih->daddr, th->dest);
  if(server == NULL){
    printk(KERN_INFO "mtcp_new(): memory allocation error...\n");
    return -1;
  }
  server->in_flow = flow;
  server->out_flow = peer;

  //printk(KERN_DEBUG "mtcp_new(): creating TCP client proxy.\n");
  client = mtcp_alloc(ih->daddr, th->dest, ih->saddr, th->source);
  if(client == NULL){
    printk(KERN_INFO "mtcp_new(): memory allocation error...\n");
    if(server) kfree(server);    
    return -1;
  }
  /* TCP connection to send out packets */
  flow->tcb_out = client;
  peer->tcb_out = server;
  /* Server connection EQV listen() */
  server->side = MTCP_SERVER; 
  server->rcv_nxt = pkt->tseq + 1;
  server->rcv_wnd = MTCP_WND;
  server->rcv_wnd_max = MTCP_WND;
  server->lastack = 0; /* unknown */
  server->snd_nxt = 0; /* unknown */
  server->mss = (MTCP_MSS > 536) ? 536 : MTCP_MSS;
  server->sack_ok = 0;
  server->state = MTCP_SYN_RCVD;
  /* Client connection EQV connect() */
  client->side = MTCP_CLIENT;
  client->in_flow = peer;
  client->out_flow = flow;
  client->snd_nxt = pkt->tseq;// + 1;
  client->lastack = pkt->tseq; 
  client->rcv_nxt = 0; /* undefined */
  client->sack_ok = 0;
  mtcp_parse_opt(client, server, pkt);
  server->rcv_wscale = client->snd_wscale;
  server->snd_wnd = ntohs(th->window) << server->snd_wscale;
  client->snd_wnd = ntohs(th->window) << client->snd_wscale;
  client->rcv_wnd = client->snd_wnd;
  client->rcv_wnd_max = client->snd_wnd;
  if(client->mss == 0) 
    client->mss = (MTCP_MSS > 536) ? 536 : MTCP_MSS;
  client->state = MTCP_SYN_SENT;
  list_add(&client->list, &mtcp_active_tcbs);
  list_add(&server->list, &mtcp_active_tcbs);
  /* start the timer */
  mtcp_timer_needed();
  return 0;
}

int mtcp_delete(struct tcb *tcb)
{
  printk(KERN_INFO "mtcp_delete(): %pI4:%d -> %pI4:%d\n", 
  	&tcb->key.saddr, ntohs(tcb->key.sport), &tcb->key.daddr, ntohs(tcb->key.dport));  
  kfree(tcb);
  return 0;
}

struct tcb *mtcp_find(struct packet *pkt)
{
  struct tcb *tcb;
  struct mtcp_key key = mtcp_getkey(pkt);
  //  printk(KERN_INFO "mtcp_find(): %pI4:%d -> %pI4:%d\n", 
  //	 &key.saddr, key.sport, &key.daddr, key.dport);
  list_for_each_entry(tcb, &mtcp_active_tcbs, list){
    if(tcb->key.saddr == key.saddr &&
       tcb->key.daddr == key.daddr &&
       tcb->key.sport == key.sport &&
       tcb->key.dport == key.dport){
      return tcb;
    }
  }
  return NULL;
}

/* TODO: handle remote peer flow */
struct tcb *mtcp_peer(struct tcb *tcb)
{
  struct tcb *peer;
  list_for_each_entry(peer, &mtcp_active_tcbs, list){
    if(peer->key.saddr == tcb->key.daddr &&
       peer->key.daddr == tcb->key.saddr &&
       peer->key.sport == tcb->key.dport &&
       peer->key.dport == tcb->key.sport){
      return peer;
    }
  }
  return NULL;
}

static void mtcp_drop_packets(struct list_head *pktlist, struct flow *flow)
{
  struct packet *pkt, *tmp;
  list_for_each_entry_safe(pkt, tmp, pktlist, list){
    list_del(&pkt->list);
    if(pkt->skb)
      kfree_skb(pkt->skb);
    packet_delete(pkt);
    if(flow != NULL)
      atomic_dec(&flow->size);
  }
}

void mtcp_purge_tcb(struct tcb *tcb)
{
  if(! list_empty(&tcb->unsent)){
      printk(KERN_DEBUG"mtcp_purge_tcb(): not all data sent\n");
      mtcp_drop_packets(&tcb->unsent, tcb->out_flow);
      INIT_LIST_HEAD(&tcb->unsent);
  }
  if(! list_empty(&tcb->unacked)){
    printk(KERN_DEBUG"mtcp_purge_tcb(): data left on ->unacked\n");
    mtcp_drop_packets(&tcb->unacked, tcb->out_flow);
    INIT_LIST_HEAD(&tcb->unacked);
  }
}

void mtcp_stop_tcb(struct tcb *tcb)
{
  /* tcb->state LISTEN not allowed here */
  if (tcb->state == MTCP_LISTEN) {
    printk(KERN_INFO "mtcp_stop_tcb(): ERROR >>> TCP NOT connected...\n");
    return;
  }
  
  if (tcb->state == MTCP_TIME_WAIT || tcb->state == MTCP_CLOSED) {
    list_del(&tcb->list);
    list_add(&tcb->list, &mtcp_closed_tcbs);
  }
  else {
    /**
     * TODO: if in an active state, send an RST to the remote end
     * and free all structures ?OR? wait a bit 
     */
    printk(KERN_INFO "mtcp_stop_tcb(): ERROR > Connection not terminated...\n");
  }
}

static void mtcp_clean_tcb(struct tcb *tcb)
{
  /* Second round of cleaning */
  if (! list_empty(&tcb->unacked)) {
    mtcp_drop_packets(&tcb->unacked, tcb->out_flow);
  }
  if (! list_empty(&tcb->unsent)) {
    mtcp_drop_packets(&tcb->unsent, tcb->out_flow);
  }
  if (! list_empty(&tcb->ooseq)) {
    mtcp_drop_packets(&tcb->ooseq, NULL);
  }
  tcb->out_flow->tcb_out = NULL;
  mtcp_delete(tcb);
  list_del(&tcb->list);
}

void mtcp_shutdown_tcb(struct tcb *tcb) 
{
  tcb->state= MTCP_CLOSED;
  mtcp_stop_tcb(tcb);
  mtcp_clean_tcb(tcb);  
} 


/**
 * Called every 500 ms and implements the retransmission timer and 
 * the timer that removes TCBs that have been in TIME-WAIT for enough 
 * time. It also increments  various timers such as the inactivity timer 
 * in each TCB.
 *
 * Automatically called from mtcp_tmr().
 */
void mtcp_slowtmr(void)
{
  struct tcb *tcb, *tmp;
  mtcp_ticks++;
  /* Steps through all of the active TCBs. */
  list_for_each_entry_safe (tcb, tmp, &mtcp_active_tcbs, list) {
    spin_lock(&tcb->lock);
    if (tcb->state == MTCP_TIME_WAIT || tcb->state == MTCP_FIN_WAIT_2) {
      tcb->timer++;
      if (tcb->timer == MTCP_WAIT_TIMEOUT) {
        tcb->state = MTCP_CLOSED;
        printk(KERN_INFO "mtcp_tmr(): closing connection\n");
	// Delete flow first
        mtcp_stop_tcb(tcb);
      }
    }
    else if (tcb->state != MTCP_CLOSED) {
      if (! list_empty(&tcb->unacked)) {
      	if (tcb->timer-- == 0) { //why NOT (++tcb->timer == MTCP_RTO)?
      	  if (tcb->nrtx == MTCP_MAXRTX || 
      	     ((tcb->state == MTCP_SYN_SENT || tcb->state == MTCP_SYN_RCVD) &&
      	      tcb->nrtx == MTCP_SYNMAXRTX)) {
      	    tcb->state = MTCP_CLOSED;
	    spin_unlock(&tcb->lock);
      	    mtcp_send_empty_seg(tcb, MTCP_RST | MTCP_ACK);
      	    printk(KERN_INFO "mtcp_tmr(): we should rexmit RST+ACK\n");
      	    return;
      	  }
      	  /* Exponential backoff */
      	  tcb->timer = MTCP_RTO << (tcb->nrtx > 4 ? 4 : tcb->nrtx);
      	  tcb->nrtx++;
      	  switch (tcb->state) {
      	  case MTCP_SYN_RCVD:
      	    mtcp_send_empty_seg(tcb, MTCP_SYN | MTCP_ACK);
      	    printk(KERN_INFO "mtcp_tmr(): rexmitting SYN+ACK\n");
      	    break;

      	  case MTCP_SYN_SENT:
      	    mtcp_send_empty_seg(tcb, MTCP_SYN);
      	    printk(KERN_INFO "mtcp_tmr(): rexmitting SYN\n");
      	    break;

      	  case MTCP_ESTABLISHED:
      	    /* Do the actual retransmission */
      	    printk(KERN_INFO "mtcp_slowtmr(): REXMITTING...\n");
      	    mtcp_rexmit_rto(tcb);
      	    break;

      	  case MTCP_FIN_WAIT_1:
      	  case MTCP_CLOSING:
      	  case MTCP_LAST_ACK:
      	    //mtcp_send_empty_seg(tcb, MTCP_FIN | MTCP_ACK);
      	    //printk(KERN_INFO "mtcp_tmr(): rexmitting FIN+ACK\n");
      	    break;

      	  case MTCP_TIME_WAIT:
            break;

          default:
      	    break;
      	  }
      	}
      }
      else if (tcb->state == MTCP_ESTABLISHED) {
	// printk(KERN_INFO "mtcp_slowtmr(): NOT POLLING...\n");
        mtcp_rexmit_rto(tcb);
      }
    }
    else { /* tcb->state is MTCP_CLOSED */
      mtcp_stop_tcb(tcb);
    }
    spin_unlock(&tcb->lock);
  }
  /* Step through all the closed tcbs for a last cleaning */
  list_for_each_entry_safe (tcb, tmp, &mtcp_closed_tcbs, list) {
    mtcp_clean_tcb(tcb);
  }
}
/**
 * Is called every MTCP_FAST_INTERVAL (250 ms) and process data previously
 * "refused" by upper layer (application) and sends delayed ACKs.
 *
 * Automatically called from mtcp_tmr().
 */
void mtcp_fasttmr(void)
{
  struct tcb *tcb, *tmp; 
  list_for_each_entry_safe (tcb, tmp, &mtcp_active_tcbs, list) {
    /* send delayed ACKs */
    spin_lock(&tcb->lock);
    if (tcb->flags & TF_ACK_DELAY) {
      printk(KERN_DEBUG"mtcp_fasttmr(): delayed ACK\n");
      tcb->flags &= ~(TF_ACK_DELAY | TF_ACK_NOW);
    }
    spin_unlock(&tcb->lock);
  }
}

/* Called periodically to dispatch TCP timers. */
void mtcp_tmr(void)
{
  static u8 slow_timer = 0;
  /* Call mtcp_fasttmr() every 250 ms */
  mtcp_fasttmr();
  /* Call mtcp_slowtmr() every 500 ms */
  if (++slow_timer & 1) mtcp_slowtmr();  
}

