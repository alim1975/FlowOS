#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "dpdk.h"
#include "arp.h"
#include "eth_out.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define MAX_WINDOW_SIZE 65535


extern int num_devices;
extern struct dpdk_device devices[MAX_DEVICES];

/*----------------------------------------------------------------------------*/
enum ETH_BUFFER_RETURN {BUF_RET_MAYBE, BUF_RET_ALWAYS};
/*----------------------------------------------------------------------------*/
/* inline void InitWriteChunks(struct rte_mempool *tx_pool, struct dpdk_burst *w_chunk)  */
/* { */
/*   int i, j, idx; */
/*   for (i = 0; i < num_devices_attached; i++) { */
/*     idx = devices_attached[i]; */
/*     for (j = 0; j < MAX_PKT_BURST; j++) { */
/*       w_chunk[idx].mbufs[j] = rte_pktmbuf_alloc(tx_pool); */
/*       if (w_chunk[idx].mbufs[j] == NULL) { */
/* 	rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc() failed\n"); */
/*       } */
/*     } */
/*     w_chunk[idx].queue.ifindex = idx; // port_id */
/*     w_chunk[idx].queue.qidx = 0; // queue_id */
/*     w_chunk[idx].recv_blocking = 0; */
/*     w_chunk[idx].cnt = 0; */
/*   } */
/* } */
/*----------------------------------------------------------------------------*/
int flowos_send_packet_burst(flowos_t flowos, int ifidx) {
  int ret = 0;
  /* struct dpdk_burst* w_chunk = ctx->w_chunk; */
  /* mtcp_manager_t mtcp = ctx->mtcp_manager; */
  /* int i; */
  /* int drop = 0; */

  /* if (w_chunk[ifidx].cnt > 0) {     */
  /*   STAT_COUNT(mtcp->runstat.rounds_tx_try);     */
  /*   ret = rte_eth_tx_burst(w_chunk[ifidx].queue.ifindex,  */
  /* 			   w_chunk[ifidx].queue.qidx,  */
  /* 			   w_chunk[ifidx].mbufs,  */
  /* 			   w_chunk[ifidx].cnt);  */
    // drop unsent packets -- see later 
    /* if (unlikely(ret < w_chunk[ifindex]->cnt)) { */
    /*   for (i = ret; i < w_chunk[ifindex]->cnt; i++) */
    /* 	rte_pktmbuf_free(w_chunk[ifindex]->mbufs[i]); */
    /* } */

/*     drop = ctx->w_chunk[ifidx].cnt - ret;     */
/*     if (ret < 0) { */
/*       TRACE_ERROR("rte_eth_tx_burst() failed to send bursts, %d:%d\n",  */
/* 		  ifidx, w_chunk[ifidx].cnt); */
/*       return ret; */
/*     }  */
/*     else { */
/* #ifdef NETSTAT */
/*       mtcp->nstat.tx_packets[ifidx] += ret; */
/* #endif /\* NETSTAT *\/ */
      
/*       for (i = 0; i < ret; i++) { */
/* #ifdef NETSTAT */
/* 	mtcp->nstat.tx_bytes[ifidx] += rte_pktmbuf_data_len(w_chunk[ifidx].mbufs[i]) + 24; */
/* #endif /\* NETSTAT *\/ */
/*       } */
      
/* #ifdef NETSTAT */
/*       if (ret != w_chunk[ifidx].cnt) { */
/* 	mtcp->nstat.tx_drops[ifidx] += (w_chunk[ifidx].cnt - ret); */
/*       } */
/* #endif /\* NETSTAT *\/ */

/*       if (ret == 0) { */
/* 	return ret; */
/*       } */
/*     } */
		
/*     if (drop > 0) { */
/*       ctx->w_chunk[ifidx].cnt = drop; */
/*       for (i = 0; i < drop; i++) { */
/*       /\* 	ctx->w_chunk[ifidx].info[i].len =  *\/ */
/*       /\* 	  ctx->w_chunk[ifidx].info[ret + i].len; *\/ */
/*       /\* 	ctx->w_chunk[ifidx].info[i].offset =  *\/ */
/*       /\* 	  ctx->w_chunk[ifidx].info[ret + i].offset; *\/ */
/*       /\* } *\/ */
/* 	ctx->w_chunk[ifidx].mbufs[i] = ctx->w_chunk[ifidx].mbufs[ret + i]; */
/*       } */
/*       //ctx->w_off[ifidx] = ctx->w_chunk[ifidx].info[drop - 1].offset + */
/*       //  (ctx->w_chunk[ifidx].info[drop - 1].len + 63) / 64 * 64; */
/*       //ctx->w_cur_idx[ifidx] += ret; */
/*       ctx->w_cur_idx[ifidx] = 0; */
/*       // TODO: GetWriteBuffer() should call alloc() */
/*       for (i = 0; i < ret; i++) { */
/* 	ctx->w_chunk[ifidx].mbufs[i + drop] = rte_pktmbuf_alloc(ctx->tx_pool); */
/* 	if (ctx->w_chunk[ifidx].mbufs[i + drop] == NULL) { */
/* 	  rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc(): error\n"); */
/* 	} */
/*       }	 */
/*     }  */
/*     else { */
/*       // TODO: should use staic linear buffer */
/*       // BUT rte_eth_tx() deletes mbufs after xmit... */
/*       for (i = 0; i < ret; i++) { */
/* 	ctx->w_chunk[ifidx].mbufs[i] = rte_pktmbuf_alloc(ctx->tx_pool); */
/* 	if (ctx->w_chunk[ifidx].mbufs[i] == NULL) { */
/* 	  rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc(): error\n"); */
/* 	} */
/*       }	 */
/*       ctx->w_chunk[ifidx].cnt = 0; */
/*       //ctx->w_off[ifidx] = 0; */
/*       ctx->w_cur_idx[ifidx] = 0; */
/*     }     */
/*   } */

  return ret;
}
/*----------------------------------------------------------------------------*/
static inline 
struct rte_mbuf *GetWriteBuffer(flowos_t flowos, 
				int method, int ifidx, int len)
{
  struct rte_mbuf *mbuf;
  /* struct dpdk_burst *w_chunk = ctx->w_chunk; */
  /* int w_idx; */
  
  /* assert(w_chunk != NULL); */

  
  /* if (ifidx < 0 || ifidx >= CONFIG.eths_num) return NULL; */
    
  /* if (ctx->w_cur_idx[ifidx] + w_chunk[ifidx].cnt >= MAX_SEND_PCK_CHUNK) { */
  /*   if (method == BUF_RET_MAYBE) { */
  /*     return NULL; */
  /*   }  */
  /*   else if (method == BUF_RET_ALWAYS) { */
  /*     if (FlushWriteBuffer(ctx, ifidx) <= 0) */
  /* 	return NULL; */
  /*   }  */
  /*   else { */
  /*     assert(0); */
  /*   } */
  /* } */
  
  /* assert(ctx->w_cur_idx[ifidx] + w_chunk[ifidx].cnt < MAX_SEND_PCK_CHUNK); */
  
  /* w_idx = w_chunk[ifidx].cnt++; */

  /* mbuf = w_chunk[ifidx].mbufs[w_idx]; */
  if (rte_mempool_get(flowos->tx_pool, (void **)&mbuf) != 0) {
    return NULL;
  }
  if (rte_pktmbuf_append(mbuf, len) == NULL) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_append(): error\n");
  }
  return mbuf;
}
/*----------------------------------------------------------------------------*/
struct rte_mbuf *flowos_eth_output(flowos_t flowos, uint16_t h_proto, 
			int nif, unsigned char* dst_haddr, uint16_t iplen)
{
  //char *buf;
  struct rte_mbuf *mbuf;
  struct ethhdr *ethh;
  int i;
  
  mbuf = GetWriteBuffer(flowos, BUF_RET_MAYBE, nif, iplen + ETHERNET_HEADER_LEN);
  if (! mbuf) {
    printf("Failed to get available write buffer\n");
    return NULL;
  }
  ethh = (struct ethhdr *) rte_pktmbuf_mtod(mbuf, struct ethhdr *);
  for (i = 0; i < ETH_ALEN; i++) {
    ethh->h_source[i] = CONFIG.eths[nif].haddr[i];
    ethh->h_dest[i] = dst_haddr[i];
  }
  ethh->h_proto = htons(h_proto);
  
  //return (uint8_t *)(ethh + 1);
  return mbuf;
}
/*----------------------------------------------------------------------------*/
