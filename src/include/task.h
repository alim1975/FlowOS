#ifndef  __TASK__
#define  __TASK__

#include "../include/channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include <rte_atomic.h>

#define MAX_CHANNELS 8
#define NAMESIZ 16

typedef void (*task_fn)(task_t This);

struct task {
  uint32_t id;
	char name[NAMESIZ];
  channel_t rxChannels[MAX_CHANNELS];
  channel_t txChannels[MAX_CHANNELS];
  uint8_t rxCount;
  uint8_t txCount;
  uint8_t nextRxIndex;
  uint8_t nextTxIndex;
  uint32_t runnable;
  rte_atomic32_t status;
  task_fn run;
  void *data;
  /* to create the list of tasks */
  TAILQ_ENTRY(task) list;
};

//typedef struct task* task_t;

int task_pool_create(uint16_t size);

void task_pool_destroy();

task_t task_create(task_fn proc, char *name, void *data, uint8_t rxCount, uint8_t txCount);

void task_destroy(task_t t);

void task_execute(task_t t);

int task_is_running(task_t t);

int task_is_runnable(task_t task);

void task_reset_running(task_t task);

void task_unblock_rx(task_t task, uint8_t index);

void task_unblock_tx(task_t task, uint8_t index);

void task_set_rx_channel(task_t task, uint8_t index, channel_t rxChannel);

void task_set_tx_channel(task_t task, uint8_t index, channel_t txChannel);

channel_t task_get_rx_channel(task_t task, uint8_t index);

channel_t task_get_tx_channel(task_t task, uint8_t index);
#endif //__TASK__
