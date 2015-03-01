#ifndef __MTCP_H__
#define __MTCP_H__

#define MTCP_CLIENT 1
#define MTCP_SERVER 2

#define MIN(x, y)                 (((int32_t)((x)-(y)) < 0) ? (x) : (y))
#define MAX(x, y)                 (((int32_t)((x)-(y)) > 0) ? (x) : (y))

#define MTCP_SEQ_LT(a, b)         ((int32_t)((a)-(b)) < 0)
#define MTCP_SEQ_LEQ(a, b)        ((int32_t)((a)-(b)) <= 0)
#define MTCP_SEQ_GT(a, b)         ((int32_t)((a)-(b)) > 0)
#define MTCP_SEQ_GEQ(a, b)        ((int32_t)((a)-(b)) >= 0)
#define MTCP_SEQ_BETWEEN(a, b, c) (MTCP_SEQ_GEQ(a,b) && MTCP_SEQ_LEQ(a,c))

#define MTCP_FIN 0x01U
#define MTCP_SYN 0x02U
#define MTCP_RST 0x04U
#define MTCP_PSH 0x08U
#define MTCP_ACK 0x10U
#define MTCP_URG 0x20U
#define MTCP_ECE 0x40U
#define MTCP_CWR 0x80U

#define MTCP_OPT_END 0x00
#define MTCP_OPT_NOP 0x01
#define MTCP_OPT_MSS 0x02
#define MTCP_OPT_WS 0x03
#define MTCP_OPT_SACKPERM 0x04
#define MTCP_OPT_SACK 0x05
#define MTCP_OPT_TIMESTAMP 0x08

#define MTCP_TTL 255
#define MTCP_MSS 536
#define MTCP_WND (4 * MTCP_MSS)

#define TF_ACK_DELAY   ((u8)0x01U)   /* Delayed ACK. */
#define TF_ACK_NOW     ((u8)0x02U)   /* Immediate ACK. */
#define TF_INFR        ((u8)0x04U)   /* In fast recovery. */
#define TF_TIMESTAMP   ((u8)0x08U)   /* Timestamp option enabled */
#define TF_NODELAY     ((u8)0x10U)   /* Disable Nagle algorithm */
#define TF_FIN         ((u8)0x20U)   /* Connection closed (FIN enqueued). */
#define TF_REXMITALL   ((u8)0x40U)   /* retransmit even the sacked packets*/
#define TF_REXMIT      ((u8)0x80U)   /* retransmit */

/* This returns a TCP header option for MSS in an uint32_t */
#define MTCP_BUILD_MSS_OPTION(_opt, _mss)		\
  (_opt) = htonl(((uint32_t)2 << 24) |			\
		 ((uint32_t)4 << 16) |			\
		 (((uint32_t)(_mss) / 256) << 8) |	\
		 ((_mss) & 255))

#define MTCP_SET_FLAGS(tcph, flags)			\
  do {							\
    (tcph)->res1 = 0;   \
    (tcph)->cwr = (flags) & MTCP_CWR ? 1 : 0;   \
    (tcph)->ece = (flags) & MTCP_ECE ? 1 : 0;   \
    (tcph)->syn = (flags) & MTCP_SYN ? 1 : 0;		\
    (tcph)->fin = (flags) & MTCP_FIN ? 1 : 0;		\
    (tcph)->ack = (flags) & MTCP_ACK ? 1 : 0;		\
    (tcph)->psh = (flags) & MTCP_PSH ? 1 : 0;		\
    (tcph)->rst = (flags) & MTCP_RST ? 1 : 0;		\
    (tcph)->urg = (flags) & MTCP_URG ? 1 : 0;		\
  }while(0)

enum mtcp_state {
  MTCP_CLOSED       = 0,
  MTCP_LISTEN       = 1,
  MTCP_SYN_SENT     = 2,
  MTCP_SYN_RCVD     = 3,
  MTCP_ESTABLISHED  = 4,
  MTCP_FIN_WAIT_1   = 5,
  MTCP_FIN_WAIT_2   = 6,
  MTCP_CLOSE_WAIT   = 7,
  MTCP_CLOSING      = 8,
  MTCP_LAST_ACK     = 9,
  MTCP_TIME_WAIT    = 10
};

struct mtcp_key{
  __be32 saddr;
  __be16 sport;
  __be32 daddr;
  __be16 dport;
} __attribute__((packed));

struct sack_block {
  uint32_t beg;
  uint32_t end;
  struct list_head list;
};

/* the TCP protocol control block */
struct tcb {
  struct mtcp_key key;
  u8 flags;
  uint32_t rcv_nxt;   /* next seqno expected */
  uint32_t rcv_wnd;   /* receiver window available */
  uint32_t rcv_wnd_max;   /* initial receiver window */
  uint32_t snd_nxt;   /* next new seqno to be sent */
  uint32_t snd_wnd;   /* sender window */
  /* fast retransmit/recovery */
  uint32_t lastack;   /* Highest acknowledged seqno. */  
  /* SACK */
  u8 sack_ok;
  struct sack_block *sack_last_update;
  struct list_head sack_blocks; /* ranges of ooseq packets */
  /* WINDOW SCALE */
  u8 snd_wscale;
  u8 rcv_wscale;
  /* TIME STAMP */
  u8       ts_enabled;
  uint32_t ts_recent;
  uint32_t ts_reply;
  uint32_t ts_lastacksent;
  /* Retransmission timer. */
  u8       timer;
  uint16_t mss;    /* maximum segment size */  
  /* RTT (round trip time) estimation variables */
  uint32_t rttest; /* RTT estimate in 500ms ticks */
  uint32_t rtseq;  /* sequence number being timed */
  int16_t sa, sv;  /* @todo document this */
  u8      rto;     /* retransmission time-out */
  u8      nrtx;    /* number of retransmissions */
  u8 ttl;
  u8 tos;
  int prio;
  enum mtcp_state state;    /* TCP state */
  struct list_head unsent;  /* Unsent (queued) segments. */
  struct list_head unacked; /* Sent but unacknowledged segments. */
  struct list_head ooseq;   /* out of seq received packets */  
  /* Locks (/!\ to be locked in the following order) */
  spinlock_t lock;  /* Protects unsent and unacked lists, and snd_nxt */
  spinlock_t rcv_nxt_lock; /* Protects rcv_nxt, ooseq and sack_blocks */
  /* FlowOS related fields */
  u8 side;                  /* TCP client or server */
  struct flow *in_flow;
  struct flow *out_flow;
  struct list_head list;
};

extern struct list_head mtcp_active_tcbs;
extern spinlock_t mtcp_lock;           /* MTCP lock */

int              mtcp_init(void);
void             mtcp_exit(void);

int              mtcp_create(struct flow *flow, struct packet *pkt);
int              mtcp_delete(struct tcb *tcb);
void             mtcp_stop_tcb(struct tcb *tcb);

struct tcb      *mtcp_find(struct packet *pkt);
struct tcb      *mtcp_peer(struct tcb *);

int              mtcp_input(struct flow *, struct packet *);
int              mtcp_process(struct tcb *tcb, struct packet *pkt);
int              mtcp_output(struct tcb *pcb);
void             mtcp_xmit_packet(struct tcb *tcb, struct packet *pkt);
int              mtcp_send_empty_seg(struct tcb *tcb, u8 flags);

void             mtcp_purge_tcb(struct tcb *tcb);
void             mtcp_parse_opt(struct tcb *tcb, struct tcb *peer, 
                          struct packet *pkt);
uint16_t         mtcp_opt_mss(struct tcphdr *);
void             mtcp_build_opt_ts(uint32_t *opts, uint32_t tsval, 
				   uint32_t tsecr);

void             mtcp_sack_insert(struct tcb *tcb, struct packet *pkt);
void             mtcp_sack_update(struct tcb *tcb, uint32_t ack);
int              mtcp_sack_build_opt(struct tcb *tcb, u8 *buf, int max);
void             mtcp_sack_sort(struct packet *pkt, uint32_t sack[8]);
int              mtcp_sack_reset_opt(struct packet *pkt);
void             mtcp_sack_print(struct list_head *sack, 
                          struct sack_block *last_update);


#define MTCP_MAXRTX    8
#define MTCP_SYNMAXRTX 5

void             mtcp_rexmit(struct tcb *tcb);
void             mtcp_rexmit_rto(struct tcb *tcb);
void             mtcp_rexmit_fast(struct tcb *tcb);
void             mtcp_rexmit_seg(struct tcb *pcb, struct packet *pkt);

/* TCP timer interval in milliseconds. */
#ifndef MTCP_TMR_INTERVAL
#define MTCP_TMR_INTERVAL       250 
#endif /* MTCP_TMR_INTERVAL */
/* Fine grained timeout in milliseconds */
#ifndef MTCP_FAST_INTERVAL
#define MTCP_FAST_INTERVAL      MTCP_TMR_INTERVAL
#endif /* MTCP_FAST_INTERVAL */
/* Coarse grained timeout in milliseconds */
#ifndef MTCP_SLOW_INTERVAL
#define MTCP_SLOW_INTERVAL      (2*MTCP_TMR_INTERVAL)  
#endif /* MTCP_SLOW_INTERVAL */
#define MTCP_WAIT_TIMEOUT     120
#define MTCP_SYN_RCVD_TIMEOUT 120
#define MTCP_RTO              3
/* TCP timer variable */
extern uint32_t mtcp_ticks;
void             mtcp_timer_needed(void);
/* Lower layer interface to TCP: */
void             mtcp_tmr     (void);  /* Must be called every
                                         TCP_TMR_INTERVAL
                                         ms. (Typically 250 ms). */
void             mtcp_slowtmr (void);
void             mtcp_fasttmr (void);

#define MTCP_PRIO_MIN    1
#define MTCP_PRIO_NORMAL 64
#define MTCP_PRIO_MAX    127

#endif /*__FLOWOS_TCP_H__*/
