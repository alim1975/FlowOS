#include <net/dst.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "messageq.h"
#include "packet.h"
#include "flow.h"
#include "mtcp.h"
#include "flowos.h"

extern void flowos_dispatch_packet(struct flow *flow, struct packet *pkt);

struct tx_thread {
  struct msgqueue* queue;      /* TX queue */
  pthread_mutex_t  lock;      /* TX queue lock */
  pthread_cond_t   condition; /* TX signal condition */
  pthread_t        thread;    /* TX handler thread */
} tx_handler;

inline void txhandler_schedule(void) {
  pthread_cond_signal(&tx_handler.condition);
}

/* send a packet to the network */
int flowos_xmit_mbuf(struct flow *flow, struct rte_mbuf *mbuf) {
  int ret;
  int buflen; /* for debugging */
  struct iphdr *iph;
  if (flow == NULL || mbuf == NULL) {
    printf("flowos_xmit_mbuf(): NULL pointer error...\n");
    return -1;
  }
  iph = (struct iphdr *)ip_hdr(mbuf);
  //  printf("xmit_mbuf(): sending mbuf to %pI4\n", &iph->daddr);
  if (! flow->rt) { 
    /* No route cache, obtain neighbour for destination */
    //printf("flowos_xmit_mbuf(): lookup route...\n");
    flow->rt = ip_route(iph->daddr); 
    if (! flow->rt) { 
      printf("flowos_xmit_mbuf(): could not find route to %pI4\n", &iph->daddr);
      return -1;
    }
  }
  mbuf->dev = flow->rt->dev;
  buflen = mbuf->len;
  ret = rte_send(mbuf);
  if (ret != 0) {
    printf("flowos_xmit_mbuf(): xmit error %d, len of mbuf is %d\n", ret, buflen);
  }
  return ret;
}

inline void txhandler_dispatch_stream(struct streamp *stp) {
  unsigned long flags;
  struct streamp *tmp;
  pthread_mutex_lock(&tx_handler.lock); 
  tmp = streamp_dup(stp);
  msgqueue_insert(tx_handler.queue, tmp);
  pthread_mutex_unlock(&tx_handler.lock);
  pthread_cond_signal(&tx_handler.condition);
}

void flowos_tx_handler(void *tx) {
  int len;
  struct tcb *tcb;
  struct iphdr *ih;
  struct tcphdr *th;
  struct udphdr *uh;
  struct packet *pkt;
  struct streamp *stp;
  struct tx_thread *txh = tx;
  while (1) {
    pthread_mutex_lock(&txh->lock);
    while (msgqueue_is_empty(txh->queue)) {
      pthread_cond_wait(&txh->contition);      
    }
    stp = msgqueue_remove(txh->queue);
    pthread_mutex_unlock(&txh->lock);
    if (stp) {
      while (SEQ_GT(stp->packet->seq, stp->flow->head->seq)) {
      	pkt = flow_remove_packet(stp->flow);
      	/* TODO: handle ADD/DEL */
      	if (pkt) {
      	  ih = (struct iphdr *)packet_ip_header(pkt);
      	  //printf("flowos_tx_handler(): sending packet with SEQ %u < %u to %pI4\n", 
      	  //pkt->seq, stp->packet->seq, &ih->daddr);
      	  if (pkt->status == PM_DIRTY) { /* dirty */
      	    // if(pkt->levels > 2){ /* FIXIT: above TCP/UDP */
      	    if (ih->protocol == IPPROTO_UDP) {
      	      uh = (struct udphdr *)((char *)ih + (ih->ihl << 2));
      	      uh->check = 0;
      	      uh->check = compute_tcpudp_checksum(ih, (char *)uh, ih->protocol);
      	    }
      	    else if (ih->protocol == IPPROTO_TCP) { 
      	      /* TODO: compute incremental checksum for small modifications */
      	      th = (struct tcphdr *)((char *)ih + (ih->ihl << 2));
      	      len = ntohs(ih->tot_len) - (ih->ihl << 2);
      	      switch (pkt->mbuf->ip_summed) {
      	      case CHECKSUM_PARTIAL:
      	      	//printf("tx_handler: PARTIAL TCP checksum\n");
      	      	th->check = ~tcp_v4_check(len, ih->saddr, ih->daddr, 0);
      	      	pkt->mbuf->csum_start = (char *)th - pkt->mbuf->head;
      	      	pkt->mbuf->csum_offset = offsetof(struct tcphdr, check);
      	    	break;

      	      default:
      	    	//print("tx_handler: Complete TCP checksum\n");
      	    	th->check = 0;
      	    	th->check = csum_tcpudp_magic(ih->saddr, ih->daddr,
      					      len, ih->protocol,
      					      csum_partial(th, len, 0));
      	    	pkt->mbuf->ip_summed = CHECKSUM_UNNECESSARY;
      	    	break;
      	      }
      	    }
      	    /* FIX ip checksum */
      	    ih->check = 0;
      	    ih->check = ip_fast_csum((char *)ih, ih->ihl);
      	  }
      	  flowos_dispatch_packet(stp->flow, pkt);
      	}
      }
      //FIXME: 1st TCP conn gets priority...
      //tcb = stp->flow->tcb_out;
      //list_move(&tcb->list, &mtcp_active_tcbs);
      streamp_delete(stp);
    }
    /* try to send something out for all active TCP connections */
    TAILQ_FOREACH (tcb, &mtcp_active_tcbs, list) {
      mtcp_output(tcb);
    }
  }
  return 0;
}

int txhandler_init(void) {  
  tx_handler.queue = msgqueue_create();
  if (! tx_handler.queue) {
    printf("txhandler_init(): failed to create TX queue\n");
    return -1;
  }
  pthread_mutex_init(&tx_handler.lock);
  pthread_cond_init(&tx_handler.condition);
  ret = pthread_create(&tx_handler.thread, NULL, (thread_fn)flowos_tx_handler, &tx_handler);
 
  return ret;
}

void txhandler_close(void)
{
  printf("FlowOS: closing TX handler\n");
  pthread_cancel(&tx_handler.thread);
  pthread_mutex_destroy(&tx_handler.lock);
  pthread_cond_destroy(&tx_handler.condition);
  msgqueue_delete(tx_queue);
}
