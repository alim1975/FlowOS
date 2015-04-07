#ifndef __FLOW__
#define __FLOW__

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>

#include <rte_spinlock.h>

#include "flowid.h"
#include "packet.h"
#include "pipeline.h"

/* maximum number of packets to buffer */
#define MAX_FLOW_SIZE 2048
#define MAX_LEVELS    8

/* A flow */
struct flow {
  /* a readable name of the flow */
  char name[80];
  /* what defines this flow */
  struct flowid id;
  /* flow capacity */
  uint16_t capacity;
  /* current size */
  uint16_t size;
  /* flow head */
  TAILQ_HEAD(, packet) head;
  rte_spinlock_t lock;
  /* protocols this flow considers */
  uint8_t protocolCount;
  char *protocols[MAX_LEVELS]; 
  /* processing pipeline for this flow */
  pipeline_t pipeline;
  /* to create the list of flows */
  TAILQ_ENTRY(flow) list;
};
typedef struct flow* flow_t;

flow_t  flow_create(flowid_t id, char *name);

void    flow_delete(flow_t flow); 

void    flow_set_protocols(flow_t flow, char *protocols);

int8_t  flow_get_level(flow_t flow, char *proto);

int     is_tcp_flow(flow_t flow);

packet_t flowos_decode_mbuf(struct rte_mbuf *mbuf, flow_t flow);

flow_t flowos_classify_packet(struct rte_mbuf *mbuf);

/*
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
*/
#endif /* __FLOW__ */
