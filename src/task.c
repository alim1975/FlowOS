#include "../include/task.h"
#include <assert.h>
#include <string.h>
#include <rte_mempool.h>

#define TXBIT  0x40000000
#define RXBIT  0x00000001
#define RUNBIT 0x80000000

static struct rte_mempool *task_pool = NULL;

static void task_init(task_t task, task_fn proc, void *data, uint8_t rxCount, uint8_t txCount) {
  uint32_t i;
  uint32_t mark;
  assert(rxCount + txCount <= 2 * MAX_CHANNELS);
  task->run = proc;
  task->data = data;
  task->rxCount = rxCount;
  task->txCount = txCount;
  rte_atomic32_init(&task->status);
  rte_atomic32_set(&task->status, 0);
  task->runnable = 0;
  for (i = 0; i < task->rxCount; i++) {
    task->runnable |= (RXBIT << i);
  }
  for (i = 0; i < task->txCount; i++) {
    task->runnable |= (TXBIT >> i);
  }
}

static void task_set_rx_ready(task_t task, uint8_t index) {
  uint32_t status;
  assert(index < task->rxCount);
  status = rte_atomic32_read(&task->status);
  status |= (RXBIT << index); 
  rte_atomic32_set(&task->status, status);
}

static void task_set_tx_ready(task_t task, uint8_t index) {
  uint32_t status;
  assert(index < task->txCount);
  status = rte_atomic32_read(&task->status);
  status |= (TXBIT >> index);
  rte_atomic32_set(&task->status, status);
}

static void task_reset_rx_ready(task_t task, uint8_t index) {
  uint32_t mask, status;
  assert(index < task->rxCount);
  mask = ~(RXBIT << index);
  status = rte_atomic32_read(&task->status);
  status &= mask;
  rte_atomic32_set(&task->status, status); 
}

static void task_reset_tx_ready(task_t task, uint8_t index) {
  uint32_t mask, status;
  assert(index < task->txCount);
  mask = ~(TXBIT >> index);
  status = rte_atomic32_read(&task->status);
  status &= mask;
  rte_atomic32_set(&task->status, status);
}

void task_set_rx_channel(task_t task, uint8_t index, channel_t rxChannel) {
  assert(index < task->rxCount);   
  assert(rxChannel);
  channel_register_consumer(rxChannel, index, task);
  task->rxChannels[index] = rxChannel;
}

void task_set_tx_channel(task_t task, uint8_t index, channel_t txChannel) {
  assert(index < task->txCount);   
  assert(txChannel);
  channel_register_producer(txChannel, index, task);
  task->txChannels[index] = txChannel;
}

int task_is_runnable(task_t task) {
  uint32_t status = RUNBIT | task->runnable;
  uint32_t expected = task->runnable;
  return rte_atomic32_cmpset(&task->status, expected, status);
}

int task_is_running(task_t task) {
  uint32_t status = rte_atomic32_read(&task->status);
  return (status & RUNBIT);
}

void task_reset_running(task_t task) {
  const uint32_t mask = ~RUNBIT; 
  uint32_t status = rte_atomic32_read(&task->status);
  status &= mask;
  rte_atomic32_set(&task->status, status);
}

void task_unblock_rx(task_t task, uint8_t index) {
  task_set_rx_ready(task, index); 
  if (task_is_runnable(task)) {
    scheduler_submit(task);
  }
}

void task_unblock_tx(task_t task, uint8_t index) {
  task_set_tx_ready(task, index); 
  if (task_is_runnable(task)) {
    scheduler_submit(task);
  }
}

int task_pool_create(uint16_t size) {
  assert(task_pool == NULL);
  task_pool = rte_mempool_create("flowos_task_pool",
				  size,
				  sizeof(struct task),
				  0, 0, 
				  NULL, NULL, NULL, NULL,
				  0, 0);
  if (! task_pool) {
    printf("task_pool_create(): failed to create task pool.\n");
    return -1;
  }
  return 0;
}

void task_pool_destroy() {
  task_pool = NULL;
}

task_t task_create(task_fn proc, void *data, uint8_t rxCount, uint8_t txCount) {
  task_t task;
  if (rte_mempool_mc_get(task_pool, (void**)&task) !=0) {
    printf("task_create(): failed to create a new task.\n");
    return NULL;
  }
  task_init(task, proc, data, rxCount, txCount);
  return task;
}

void task_destroy(task_t task) {
  rte_mempool_put(task_pool, task);
}