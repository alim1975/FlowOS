#ifndef __STREAMP_H__
#define __STREAMP_H__

#include "flow.h"
#include "packet.h"

struct streamp {
  int pos;
  uint8_t level;
  struct flow *flow;
  struct packet *packet;
  char *ptr;
};

int streamp_cache_init(void);

void streamp_cache_delete(void);

struct streamp *streamp_init(struct streamp *stp, struct flow *flow, uint8_t level);

struct streamp *streamp_create(struct flow *, uint8_t level);

char *streamp_set_packet(struct streamp *, struct packet *);

void streamp_delete(struct streamp *);

char *streamp_post_inc(struct streamp *stp, struct streamp *limit);

char *streamp_pre_inc(struct streamp *stp, struct streamp *limit);

void streamp_map(struct streamp *dst, struct streamp *src);

struct streamp *streamp_dup(struct streamp *stp2);

int streamp_compare(void *p1, void *p2);

void streamp_setpos(void *n, int pos);

int streamp_getpos(void *n);

struct streamp streamp_find(char *pattern, struct streamp *head,
			     struct streamp *tail);

int streamp_remove(struct streamp *st1, struct streamp *st2);

//int streamp_match(struct ts_config *conf, struct streamp *head,  
//		  struct streamp *tail);

//int streamp_find_and_replace(struct ts_config *conf, char *sbst,
//			     struct streamp *head, struct streamp *tail);

int streamp_strncmp(struct streamp *stp, char *str, size_t len);

int streamp_strnicmp(struct streamp *stp, char *str, size_t len);

uint32_t streamp_count_bytes(struct streamp *stp1, struct streamp *stp2);

char *streamp_move_next(struct streamp *stp, uint32_t count);

//int streamp_read_line(struct line *line, struct streamp *start, struct streamp *limit);

//void streamp_copy_line(char *msg, struct streamp *stp, int len);

#define streamp_valid_stream(stp, level) \
 ((stp)->packet->parray[level] != NULL && (stp)->ptr >= (stp)->packet->parray[level])

#define streamp_packet_start(stp) (stp)->packet->parray[(stp)->level]

#define streamp_packet_end(stp) (stp)->packet->parray[(stp)->packet->levels - 1]

int streamp_packet_remainingbytes(struct streamp *stp); 

int streamp_packet_totalbytes(struct streamp *stp);

void streamp_moveto_end(struct streamp *stp);

#define streamp_is_equal(st1, st2)  ((st1)->packet == (st2)->packet && (st1)->ptr == (st2)->ptr)

#define streamp_is_null(st)  (st == NULL || (st)->ptr == NULL)

#endif
