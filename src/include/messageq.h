#ifndef __MSGQUEUE_H__
#define __MSGQUEUE_H__

struct qnode{
  void *data;
  struct qnode *next;
};

struct msgqueue{
  struct qnode *in;
  struct qnode *out;
}; 

#define msgqueue_is_empty(_mq) ((_mq)->in == (_mq)->out)

int msgqueue_cache_init(void);
void msgqueue_cache_delete(void);
struct msgqueue *msgqueue_create(void);
void msgqueue_delete(struct msgqueue *);
void msgqueue_insert(struct msgqueue *, void *);
void *msgqueue_remove(struct msgqueue *);

#endif /* __MSGQUEUE_H__ */
