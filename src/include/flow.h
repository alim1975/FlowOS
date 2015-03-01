#ifndef __FOS_FLOW__
#define __FOS_FLOW__

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>
#include <pthread.h>

#include <rte_ethdev.h>

#include "flowid.h"
#include "pipeline.h"
#include "packet.h"

/* maximum number of packets to buffer */
#define MAX_FLOW_SIZE 2048
#define MIN_HEAP_SIZE 16
#define MAX_LEVELS    8

/* A flow */
struct flow {
  /* a readable name of the flow */
  char name[80];
  /* what defines this flow */
  struct flowid id;
  /* id->in_port to map */
  struct rte_eth_dev *idev;
  /* output route */
  //struct rtable *rt;
  void *tcb_out;
  /* flow capacity */
  int capacity;
  /* current szie */
  volatile unsigned size;
  /* flow head */
  struct packet *head; 
  /* flow tail */
  struct packet *tail; 
  /* to lock flow tail */
  pthread_mutex_t tail_lock;
  /* protocols this flow considers */
  uint8_t num_protos;
  char *protocols[MAX_LEVELS]; 
  /* processing pipeline for this flow */
  struct pipeline *pipeline;
  /* to create the list of flows */
  TAILQ_ENTRY(flow) list;
};

typedef TAILQ_HEAD(, flow) flow_head_t;

struct flow   *flow_create(struct flowid *id, char *fname);
void           flow_delete(struct flow *); 
void           flow_set_protocols(struct flow *flow, char *protos);
uint8_t        flow_get_level(struct flow *flow, char *proto);
int            is_tcp_flow(struct flow *);
int            flow_attach_pm(struct flow *, pthread_t , uint8_t); 
int            flow_detach_pm(char *, char *);
void           flow_append_packet(struct flow *flow, struct packet *pkt);
struct packet *flow_remove_packet(struct flow *flow);
struct flow   *flowos_match_mbuf_to_flow(struct flow *, struct rte_mbuf *mbuf);

extern struct flow *flowos_find_flow(char *fname);
extern void         flowos_save_flow(struct flow *flow);
extern int          flowos_remove_flow(char *fname);

extern pthread_t *flowos_find_pm(char *name);
extern void      flowos_save_pm(pthread_t *);
extern int       flowos_remove_pm(char *name);

#endif /* _FLOW_H_ */
