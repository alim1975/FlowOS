#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_mempool.h>
#include <rte_malloc.h>

#include "flow.h"
#include "streamp.h"
#include "pmodule.h"
#include "packet.h"

static struct rte_mempool *streamp_cache;

int streamp_cache_init(void) {
  streamp_cache = rte_mempool_create("flowos_streamp_cache", 
				     POOL_SIZE,
				     sizeof(struct streamp),
				     0, 0,
				     NULL, NULL, NULL, NULL,
				     0, 0);
  if (! streamp_cache) {
    printf("streamp_cache_init(): failed to create streamp cache\n");
    return -1;
  }
  return 0;
}

inline void streamp_cache_delete(void) {
  streamp_cache = NULL;
}

struct streamp *streamp_init(struct streamp *stp, struct flow *flow, uint8_t level) {
  if (! stp) {
    if (rte_mempool_sc_get(streamp_cache, (void **)&stp) != 0) {
      printf("streamp_init(): failed to allocate memory\n");
      return NULL;
    }
  }
  stp->flow = flow;
  stp->level = level;
  stp->pos = 0;
  stp->packet = NULL;
  stp->ptr = NULL;
  
  return stp;
}

struct streamp *streamp_create(struct flow *flow, uint8_t level) {
  struct streamp *stp;

  if( rte_mempool_sc_get(streamp_cache, (void **)&stp) != 0) {
    printf("streamp_create(): failed to allocate memory\n");
    return NULL;
  }
  stp->flow = flow;
  stp->level = level;
  stp->pos = 0;
  stp->packet = NULL;
  stp->ptr = NULL;
  
  return stp;
}

inline void streamp_delete(struct streamp *stp) {
  rte_mempool_put(streamp_cache, stp);
}

/* set the current packet and the ptr to the beginning of the stream */
char *streamp_set_packet(struct streamp *stp, struct packet *pkt) {
  assert(stp);
  assert(pkt);
  stp->packet = pkt;
  /* in case of dummy node! */ 
  if(pkt->levels == 0) stp->ptr = NULL;  
  else stp->ptr = pkt->parray[stp->level];  

  return stp->ptr;
}

/* create a duplicate stream pointer */
struct streamp *streamp_dup(struct streamp *src) {
  struct streamp *dst;
  assert(src);
  if (rte_mempool_sc_get(streamp_cache, (void **)&dst) != 0) {
    printf("streamp_dup(): Failed to copy stream pointer\n");
    return NULL;
  }
  dst->packet = src->packet;
  dst->ptr = src->ptr;
  dst->flow = src->flow;
  dst->level = src->level;
  dst->pos = src->pos;
  
  return dst;
}

/* map a stream pointer from one stream to another */
void streamp_map(struct streamp *dst, struct streamp *src) {
  assert(dst);
  assert(src);
  dst->packet = src->packet;   
  /* NOTE: the tail node has no skb and parray */
  if (src->packet->levels == 0) {
    dst->ptr = NULL; 
  } 
  /* within src's packet dst is at lower level, so src is valid for sure */
  else if (dst->level <= src->level) {
    dst->ptr = src->ptr;  
  /* dst is at higher level, so must check if any valid level exists in packet
     if valid (higher) level than dst exist in packet, 
     check if src ptr points into valid zone */
  }
  else if (src->packet->parray[dst->level] != NULL && 
	   src->ptr >= src->packet->parray[dst->level]) {
    dst->ptr = src->ptr;
  }
  
  /* src ptr not valid for dst level, 
     so must make dst point to null */
  else { 
    dst->ptr = NULL;
  }
}

/* get the number of bytes left in the current packet */
int streamp_packet_remainingbytes(struct streamp *stp) {
  int count = 0;
  assert(stp);
  if (stp->ptr && stp->ptr < packet_end(stp->packet)) {
    count = packet_end(stp->packet) - stp->ptr;
  }
  return count;
}

/* get the total number of bytes in the current packet */
int streamp_packet_totalbytes(struct streamp *stp) {
  int count = 0;
  if (stp->packet->parray[stp->level] != NULL) {
    count = packet_end(stp->packet) - packet_start(stp->packet, stp->level);
  }
  return count;
}

/* move the stream pointer to the last byte of the current packet */
void streamp_moveto_end(struct streamp *stp) {
  assert(stp);
  if (stp->packet->parray[stp->level] != NULL) {
    stp->ptr = stp->packet->parray[stp->packet->levels - 1];
  }
}

/* count the number of bytes between two stream pointers of a stream */
uint32_t streamp_count_bytes(struct streamp *p1, struct streamp *p2) {
  struct streamp st;
  uint32_t count, rest;
  assert(p1);
  assert(p2);
  st = *p1;
  count = 0;
  while (1) {
    if (SEQ_GT(p2->packet->seq, st.packet->seq)) { 
      rest = streamp_packet_remainingbytes(&st);
      count += rest;
      streamp_set_packet(&st, TAILQ_NEXT(st.packet, list));
    }
    else { /* last packet */
      if (st.ptr != NULL && p2->ptr != NULL && p2->ptr > st.ptr) {
	rest = (p2->ptr - st.ptr);
	count += rest;
      }
      break;
    }
  }
  return count;
}

/*
char* streamp_pre_inc(struct streamp* stp, struct streamp *limit)
{
   if (stp->packet->parray == NULL || streamp_is_equal(stp, limit)) 
      return NULL;
   //end of a packet or there is nothing valid in the packet
   if (stp->ptr == stp->packet->parray[stp->stream->levels - 1 ] || stp->ptr == NULL) { 
      while(stp->packet->next->rank <= limit->packet->rank)
         if(streamp_set_packet(stp, stp->packet->next))
            break;
      if(limit->ptr == NULL && stp->packet->rank == limit->packet->rank)
         stp->ptr = NULL;
   }   
   else
      stp->ptr++;
   
   return stp->ptr;
}
*/
    
/* return the current byte pointer and advance the pointer to the next byte */
char *streamp_post_inc(struct streamp *stp, struct streamp *limit) {
  char *cp;
  assert(stp);
  assert(limit);
  /* limit must be greater than current pointer */
  if (SEQ_GT(stp->packet->seq, limit->packet->seq)) {
    printf("streamp_inc(): ERROR limit < ptr\n");
    return NULL;
  }
  /* current ptr in dummy node */
  if (stp->packet->parray == NULL) return NULL;  
  /* current == limit */
  if (stp->packet == limit->packet && 
      (limit->ptr == NULL || stp->ptr == limit->ptr))
    return NULL; 
  /* save current pointer */
  cp = stp->ptr;
  /* end of a packet or there is nothing valid in the packet */
  if (stp->ptr == NULL || stp->ptr == packet_end(stp->packet)) { 
    while (SEQ_GT(limit->packet->seq, stp->packet->seq)) {
      /* move to next packet */     
      if (streamp_set_packet(stp, TAILQ_NEXT(stp->packet, list)))
	break; /* if ptr is valid */
    }
    /* last packet */
    if ((stp->packet->seq == limit->packet->seq) && (limit->ptr == NULL))
      stp->ptr = NULL;
  }
  else {
    /* inside a packet */
    stp->ptr++;
  }  
  return cp;
}

/* advance the stream pointer by 'count' bytes.
   assumes that the stream pointed to 
   by 'stp' has at least 'count' bytes */
char *streamp_move_next(struct streamp *stp, uint32_t count) {
  uint32_t rest; 
  assert(stp);
  do {
    rest = streamp_packet_remainingbytes(stp);
    if (rest > count) {
      stp->ptr += count;
      count = 0;
    }
    else {
      streamp_set_packet(stp, TAILQ_NEXT(stp->packet, list));
      count -= rest;
    }
  } while(count > 0);

  return stp->ptr;
}

/* compare a given string of length 'len' with the bytes
   starting from the stream pointer. assumes ptr is valid and 
   there are at least 'len' bytes in the stream */
int streamp_strncmp(struct streamp *stp, char *string, size_t len) {
  int ret;
  size_t rest;
  struct streamp st;
  assert(stp);
  st = *stp; 
  do {
    rest = streamp_packet_remainingbytes(&st);
    if (rest >= len) {
      return strncmp(st.ptr, string, len);
    }
    else {
      ret = strncmp(st.ptr, string, rest);
      if (ret) {
	return ret;
      }
      else {
	len -= rest;
	/* skip any non-data packet 
	   NOTE: if no more data in the stream this loop 
	   will NOT terminate */
	while (! streamp_set_packet(stp, TAILQ_NEXT(stp->packet, list)));
      }
    }
  } while(len > 0);

  return 0;
}

/* compare a given string of length 'len' with the bytes
   starting from the stream pointer ignoring the case. assumes 
   ptr is valid and there are at least 'len' bytes in the stream */
int streamp_strnicmp(struct streamp *stp, char *string, size_t len) {
  int ret;
  size_t rest;
  struct streamp st;
  assert(stp);
  st = *stp; 
  do {
    rest = streamp_packet_remainingbytes(&st);
    if(rest >= len) {
      return strncasecmp(st.ptr, string, len);
    }
    else {
      ret = strncasecmp(st.ptr, string, rest);
      if (ret) {
	return ret;
      }
      else {
	len -= rest;
	/* skip non-data packets. 
	   NOTE: if there are less than 'len' bytes
	   in the stream, this loop will NOT terminate!	*/
	while (! streamp_set_packet(stp, TAILQ_NEXT(stp->packet, list)));
      }
    }
  } while(len > 0);

  return 0;
}

char *streamp_getchar(struct streamp *stp) {
  return NULL;
}

/* advance the stream pointer to the '\n' character and return the line
   with starting pointer and the number of bytes. if a '\n' is not found,
   move the stream pointer to the limit */
/*
struct streamp *streamp_readline(struct streamp *stp)
{
  char *cp;
  int i = 0;
  struct streamp *endline = streamp_dup(stp);
  if(! endline){
    printk(KERN_INFO "streamp_readline(): ENOMEM\n");
    return NULL;
  }
  // streamp_inc UPDATEs from
  do{
    cp = streamp_post_inc(endline, limit);
    if(*cp == '\n'){
      return endline;
    }
    else if(cp == NULL){
      
    }
  }
  //Block
}
EXPORT_SYMBOL(streamp_readline);
*/

/* /\* copy 'len' bytes from the stream pointer to 'msg'.  */
/*    assumes the stream has at least 'len' bytes. *\/ */
/* void streamp_copy_line(char *msg, struct streamp *stp, int len) */
/* { */
/*   int size, rest; */
/*   struct streamp st; */
/*   msg[0] = '\0'; */
/*   st = *stp; */
/*   while(1){ */
/*     rest = streamp_packet_remainingbytes(&st); */
/*     size = rest > len ? len : rest;  */
/*     strncat(msg, st.ptr, size); */
/*     len -= size; */
/*     if(len == 0) */
/*       break; */
/*     /\* NOTE: if there are no more data in the stream */
/*       this loop will not terminate *\/ */
/*     while(! streamp_set_packet(&st, st.packet-> next));     */
/*   };     */
/* } */
/* EXPORT_SYMBOL(streamp_copy_line); */

/* compare two stream pointers based on the packet sequence. 
   callback for heap to sort stream pointers */
int streamp_compare(void *p1, void *p2) {
  struct streamp *sp1, *sp2;
  sp1 = (struct streamp *)p1;
  sp2 = (struct streamp *)p2;
  if (SEQ_GT(sp1->packet->seq, sp2->packet->seq)) {
    return 1;
  }
  else if (SEQ_GT(sp2->packet->seq, sp1->packet->seq)) {
    return -1;
  }
  else {
    return (sp1->ptr - sp2->ptr);   
  }
}

/* callback for heap to set index */
void streamp_setpos(void *node, int pos) {
  struct streamp *stp;
  assert(node);
  stp = node;
  stp->pos = pos;
}

/* callback for heap to get index */
int streamp_getpos(void *node) {
  struct streamp *stp;
  assert(node);
  stp = node;
  return stp->pos;
}

int streamp_remove(struct streamp *st1, struct streamp *st2) {
  char *ptr;
  int count;
  struct packet *pkt;
  if (st1 == NULL || st2 == NULL || streamp_compare(st1, st2) >= 0) {
    printf("streamp_remove(): failed to delete data\n");
    return -1;
  }
  /* single packet */
  if (st1->packet->seq == st2->packet->seq) {
    count = st2->ptr - st1->ptr;
    packet_del_bytes(st1->packet, st1->ptr, count);
  }
  else { /* multiple packets */
    pkt = st1->packet;
    while (pkt) {
      if(pkt == st1->packet) {
	/* app data starting at ptr */
	ptr = st1->ptr; 
      }
      else {
	/* start of app data */
	ptr = packet_start(pkt, st1->level); 
      }

      if (pkt != st2->packet) {
	/* delete from ptr to end of packet */
	packet_del_bytes(pkt, ptr, -1); 
      }
      else {
      	count = st2->ptr - packet_start(pkt, st2->level);
	/* delete 'count' bytes from ptr */
      	packet_del_bytes(pkt, ptr, count); 
      }

      if(pkt == st2->packet) pkt = NULL;
      else pkt = TAILQ_NEXT(pkt, list);
    }
  }
  return 0;
}

int streamp_insert(struct streamp *stp, const char *text) {
  /* TODO */
  return 0;
}

struct streamp streamp_find(char *pattern, 
			    struct streamp *head,  
			    struct streamp *tail)
{
  char *err;
  struct packet *pkt; 
  struct streamp tmp;
  struct ts_state state;
  unsigned int pos;
  static struct ts_config *conf = NULL; 
  if(pattern == NULL && conf == NULL){
    printk(KERN_INFO "streamp_find(): search pattern required for "
	   "textsearch initialization\n");
    tmp.ptr = NULL;
    tmp.packet = NULL;
    tmp.flow = NULL;
    return tmp;    
  }
  streamp_init(&tmp, head->flow, head->level);
  if(pattern != NULL){
    if(conf && (strlen(pattern) != textsearch_get_pattern_len(conf) ||
		strcmp(pattern, textsearch_get_pattern(conf)) != 0)){
      textsearch_destroy(conf);
      conf = NULL;
    }
    if(conf == NULL){
      conf = textsearch_prepare("kmp", pattern, strlen(pattern),
				GFP_ATOMIC, TS_AUTOLOAD);
      if(IS_ERR(conf)){
	err = (char *)PTR_ERR(conf);
	printk(KERN_INFO "textsearch_prepare() failed: %s\n", err);
	tmp.ptr = NULL;
	tmp.packet = NULL;
	tmp.flow = NULL;
	return tmp;
      }
    }
  }
  if(head->packet == tail->packet && head->ptr != NULL && tail->ptr != NULL){
    memset(&state, 0, sizeof(struct ts_state));
    streamp_map(&tmp, head);
    pos = textsearch_find_continuous(conf, &state, head->ptr, 
				     tail->ptr - head->ptr);	
    if(pos != UINT_MAX){ 
      tmp.ptr+= pos;
      return tmp;
    }    
  }
  else{
    for(pkt = head->packet, streamp_map(&tmp, head);
	pkt != tail->packet;
	pkt = pkt->next, streamp_set_packet(&tmp, pkt)){
      if(tmp.ptr && streamp_packet_remainingbytes(&tmp) > 0){
	memset(&state, 0, sizeof(struct ts_state));
	pos = textsearch_find_continuous(conf, &state, tmp.ptr, 
					 packet_end(pkt) - tmp.ptr);
	if(pos != UINT_MAX){ 
	  tmp.ptr+= pos;
	  return tmp;
	}
      }
    }  
  }
  tmp.ptr = NULL;
  tmp.packet = NULL;
  tmp.flow = NULL;
  return tmp;
}

/*
int streamp_match(struct ts_config *conf, 
		  struct streamp *head, 
		  struct streamp *tail)
{
  struct packet *pkt; 
  struct streamp *tmp;
  struct ts_state state;
  int len, count = 0;
  unsigned int pos, from, to;
  if(head == NULL || head->ptr == NULL){
    printk(KERN_INFO "streamp_match(): head == NULL\n");
    return 0;
  }
  if(tail == NULL || tail->packet == NULL){
    printk(KERN_INFO "streamp_match(): tail == NULL\n");
    return 0;
  }
  if(SEQ_GT(head->packet->seq, tail->packet->seq)){
    printk(KERN_INFO "streamp_match(): head > tail\n");
    return 0;
  }
  for(pkt = head->packet, tmp = streamp_dup(head);
      pkt != tail->packet;
      pkt = pkt->next, streamp_set_packet(tmp, pkt)){
    if(tmp->ptr && (len = streamp_packet_remainingbytes(tmp)) > 0){
      memset(&state, 0, sizeof(struct ts_state));
      from = tmp->ptr - (char *)pkt->skb->data;
      to = packet_end(pkt) - (char *)pkt->skb->data;      
      pos = skb_find_text(pkt->skb, from, to, conf, &state); 
      while(pos != UINT_MAX){ 
	count++;
	pos = textsearch_next(conf, &state);
      }
    }
  }
  streamp_delete(tmp);  
  return count;
}
EXPORT_SYMBOL(streamp_match);

int streamp_find_and_replace(struct ts_config *conf, char *sbst,
			     struct streamp *head, struct streamp *tail)
{ 
  // TODO: treat overlaps of patterns over several packets 
  // TODO: improve efficiency in case of multiples matches 
  struct packet *pkt; 
  struct streamp *tmp;
  struct ts_state state;
  int patlen, sbstlen, remlen, opt, count = 0;
  unsigned int pos, from, to;
  struct iphdr *ih;

  if(head == NULL || head->ptr == NULL){
    printk(KERN_INFO "streamp_replace(): head == NULL\n");
    return 0;
  }
  if(tail == NULL || tail->packet == NULL){
    printk(KERN_INFO "streamp_replace(): tail == NULL\n");
    return 0;
  }
  if(SEQ_GT(head->packet->seq, tail->packet->seq)){
    printk(KERN_INFO "streamp_replace(): head > tail\n");
    return 0;
  }
  patlen = textsearch_get_pattern_len(conf);
  sbstlen = strlen(sbst);
  opt = sbstlen - patlen;
  for(pkt = head->packet, tmp = streamp_dup(head);  
      pkt != tail->packet;
      pkt = pkt->next, streamp_set_packet(tmp, pkt)){
    if(tmp->ptr && (remlen = streamp_packet_remainingbytes(tmp)) > 0){
      pos = 0;
      memset(&state, 0, sizeof(struct ts_state));
      from = tmp->ptr - (char *)pkt->skb->data; 
      to = packet_end(pkt) - (char *)pkt->skb->data;
      pos = skb_find_text(pkt->skb, from, to, conf, &state); 
      while(pos != UINT_MAX && from < to){
      	if(opt == 0){      // substitue 
      	  memcpy(tmp->ptr + pos, sbst, strlen(sbst));
          pkt->status = PM_DIRTY; // dirty 
          count++;
      	}
      	else if(opt < 0){  // shrinks 
          memmove(tmp->ptr + pos + sbstlen, tmp->ptr + pos + patlen,
            remlen - pos - patlen);
          skb_trim(pkt->skb, pkt->skb->len + opt);
      	  memcpy(tmp->ptr + pos, sbst, strlen(sbst));
          ih = (struct iphdr *)packet_ip_header(pkt);
          ih->tot_len = htons(ntohs(ih->tot_len) + opt);
          pkt->tlen += opt;
          pkt->status = PM_DIRTY; // dirty 
          count++;
      	}
      	else{              // expands 
      	  if(opt < skb_tailroom(pkt->skb)){
            skb_put(pkt->skb, opt);
            memmove(tmp->ptr + pos + sbstlen, tmp->ptr + pos + patlen,
             remlen - pos - patlen);
            memcpy(tmp->ptr + pos, sbst, strlen(sbst));
            ih = (struct iphdr *)packet_ip_header(pkt);
            ih->tot_len = htons(ntohs(ih->tot_len) + opt);
            pkt->tlen += opt;
            pkt->status = PM_DIRTY; // dirty 
            count++;
          }
          else{
            printk(KERN_INFO
              "streamp_find_and_replace(): skb too short, substitution cancelled");
          }
      	}
        memset(&state, 0, sizeof(struct ts_state));
        tmp->ptr += pos + sbstlen;
        from = tmp->ptr - (char *)pkt->skb->data;
        pos = skb_find_text(pkt->skb, from, to, conf, &state); 
      }
    }   
  }
  streamp_delete(tmp);

  return count;  
}
EXPORT_SYMBOL(streamp_find_and_replace);
*/
