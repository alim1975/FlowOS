#include "../include/scheduler.h"

#include <assert.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>

static scheduler_t SCHEDULER = NULL;

static int task_executor(void *data) {
  task_t task;
  while (true) {
    pthread_mutex_lock(&SCHEDULER->lock);
    task = NULL;
    while(rte_ring_dequeue(SCHEDULER->taskq, (void**)&task) != 0) {
      pthread_cond_wait(&SCHEDULER->condition, &SCHEDULER->lock);
    }
    pthread_mutex_unlock(&SCHEDULER->lock);
    //printf("scheduler starts task %u\n", task->id);
    task->run(task);
    task_reset_running(task);
  }
  return 0;
}

void scheduler_init(size_t size) {
  int i, j;
  unsigned lcore;
  assert(SCHEDULER == NULL);
  SCHEDULER = (scheduler_t)rte_malloc("scheduler_t", sizeof(struct scheduler), 0);
  if (SCHEDULER == NULL) {
    rte_exit(EXIT_FAILURE, "Failed to create thread pool.");
  }
  // allocate memory on socket 0
  SCHEDULER->taskq = rte_ring_create("task-queue",
		  	  TASK_QUEUE_LENGTH, 0, 0); 
  if (! SCHEDULER->taskq) {
    rte_free(SCHEDULER);
    rte_exit(EXIT_FAILURE, "Failed to create task queue.");
  }
  // Scheduler size is limited by the number of slave lcores.
  // 1 master and 1 reserved for the TCP thread
  lcore = rte_lcore_count();
  printf("No. of lcores found=%d\n", lcore);
  lcore -= 1;
  assert(size <= lcore);
  SCHEDULER->size = size;
  pthread_cond_init(&SCHEDULER->condition, NULL);
  pthread_mutex_init(&SCHEDULER->lock, NULL); 
  i = 0; // 1st slave lcore is reserved for mTCP
  RTE_LCORE_FOREACH_SLAVE(lcore) {
    if (i++ < 1) continue;
    //if (i > SCHEDULER->size) break;
    printf ("Creating %d-th worker thread.\n", i);
    if (rte_eal_remote_launch(task_executor, SCHEDULER, lcore) != 0) {
      rte_free(SCHEDULER);
      rte_exit(EXIT_FAILURE, "Failed to launch worker thread %d\n", i);
    }
  }
}

void scheduler_destroy() {
  //unsigned lcore;
  //int i = 0;
  //RTE_LCORE_FOREACH_SLAVE(lcore) {
  // if (i++ < 1) continue;
  // if (i > sch->size) break;
  //  rte_eal_remote_cancel(lcore);
  //}
  rte_free(SCHEDULER);
}

void scheduler_submit(task_t task) {
  pthread_mutex_lock(&SCHEDULER->lock);
  rte_ring_enqueue(SCHEDULER->taskq, task);
  pthread_cond_broadcast(&SCHEDULER->condition);
  pthread_mutex_unlock(&SCHEDULER->lock);
}
