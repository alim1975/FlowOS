#include "messageq.h"

#include <stdio.h>

#include <rte_mempool.h>
#include <rte_malloc.h>

#define POOL_SIZE 10000

static struct rte_mempool *qmsg_cache;

int msgqueue_cache_init(void) {
  qmsg_cache = rte_mempool_create("flowos_qmsg_cache",
				  POOL_SIZE,
				  sizeof(struct qnode),
				  0, 0, 
				  NULL, NULL, NULL, NULL,
				  0, 0);
  if (! qmsg_cache) {
    printf("qmsg_cache_init(): failed to create streamp cache\n");
    return -1;
  }
  return 0;
}

inline void msgqueue_cache_delete(void) {
  // rte_mempool_free();
  qmsg_cache = NULL;
}

static struct qnode *qnode_create(void) {
  struct qnode *node;
  if (rte_mempool_sc_get(qmsg_cache, (void **)&node) != 0) {
    printf("msgqnde_new(): failed to allocate memory\n");
    return NULL;
  }
  node->next = NULL;
  return node;
}

static inline void qnode_delete(struct qnode *node) {
  rte_mempool_put(qmsg_cache, node);
}

struct msgqueue *msgqueue_create(void) {
  struct msgqueue *mq = rte_malloc("msgqueue", sizeof(struct msgqueue), 0);
  if (mq == NULL) {
    printf("Failed to create message queue\n");
    return NULL;
  }
  mq->in = mq->out = qnode_create(); /* Dummy node */

  return mq;
}

void msgqueue_delete(struct msgqueue *mq) {
  void *info;
  while ((info = msgqueue_remove(mq))) {
    // FIXIT: mq->free(info);
  }
  qnode_delete(mq->in);
  rte_free(mq);
}

void msgqueue_insert(struct msgqueue *mq, void *info) {
  mq->in->next = qnode_create();
  if (mq->in->next == NULL) {
    printf("msgq_insert(): failed to creat new node\n");
    return;
  }
  mq->in->data = info;
//  smp_wmb();
  mq->in = mq->in->next;
}

void *msgqueue_remove(struct msgqueue *mq) {
  void *info;
  struct qnode *node;
//  smp_rmb();
  if (msgqueue_is_empty(mq)) return NULL;
  node = mq->out;
  info = node->data;
  node->data = NULL;
  qnode_delete(node);
//  smp_wmb();
  mq->out = mq->out->next;
  return info;
}
