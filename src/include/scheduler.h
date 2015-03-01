#ifndef __SCHEDULER__
#define __SCHEDULER__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <rte_ring.h>

#include "task.h"

#define TASK_QUEUE_LENGTH 1024

struct scheduler {
  size_t size;
  struct rte_ring *taskq;
  pthread_cond_t condition;
  pthread_mutex_t lock;
};
typedef struct scheduler* scheduler_t;

void scheduler_submit(task_t task);

void scheduler_init(size_t size);

void scheduler_destroy();

#endif //__SCHEDULER__
