#include "../include/channel.h"
#include "../include/task.h"

#include <rte_mempool.h>
#include <assert.h>

static struct rte_mempool *channel_pool = NULL;

int channel_pool_create(uint16_t size, uint16_t ch_size) {
  assert(channel_pool == NULL);
  channel_pool = rte_mempool_create("flowos_channel_pool",
				    size,
				    sizeof(struct channel) + sizeof(void *) * ch_size,
				    0, 0, 
				    NULL, NULL, NULL, NULL,
				    0, 0);
  if (! channel_pool) {
    printf("channel_pool_create(): failed to create channel pool.\n");
    return -1;
  }
  return 0;
}

void channel_pool_destroy() {
  channel_pool = NULL;
}

channel_t channel_get() {
  channel_t channel;
  if (rte_mempool_mc_get(channel_pool, (void**)&channel) != 0) {
    printf("channel_get(): channel pool is empty.\n");
    return NULL;
  }
  //channel_init(channel);
  return channel;
}

void channel_put(channel_t channel) {
  rte_mempool_put(channel_pool, channel);
}

int channel_is_full(channel_t channel) {
  return rte_atomic16_cmpset(&channel->size, channel->capacity, channel->capacity);
}

int channel_is_empty(channel_t channel) {
  return rte_atomic16_cmpset(&channel->size, 0, 0);
}

void channel_insert(channel_t channel, void *item) {
  uint16_t index = rte_atomic16_read(&channel->writeIndex);
  assert(! channel_is_full(channel));
  channel->array[index] = item;
  index  = (index + 1) % channel->capacity;
  rte_atomic16_set(&channel->writeIndex, index);
  rte_atomic16_inc(&channel->size);
  if (channel->consumer) {
    task_unblock_rx(channel->consumer, channel->consumerIndex);
  }
}

void *channel_remove(channel_t channel) {
  void *item;
  uint16_t index = rte_atomic16_read(&channel->readIndex);
  assert(! channel_is_empty(channel));
  item = channel->array[index];
  index = (index + 1) % channel->capacity;
  rte_atomic16_set(&channel->readIndex, index);
  rte_atomic16_dec(&channel->size);
  if (channel->producer) {
    task_unblock_tx(channel->producer, channel->producerIndex);
  }
}

void *channel_peek(channel_t channel) {
  assert(! channel_is_empty(channel));
  return channel->array[rte_atomic16_read(&channel->readIndex)];
}

void channel_close(channel_t channel) {
  rte_atomic16_set(&channel->closed, 1);
  if (channel->consumer) {
    task_unblock_rx(channel->consumer, channel->consumerIndex);
  }
}

int channel_is_closed(channel_t channel) {
  return rte_atomic16_read(&channel->closed);
}

void channel_register_producer(channel_t channel, uint8_t index, task_t producer) {
  assert(channel->producer == NULL);
  assert(index < producer->txCount);
  channel->producerIndex = index;
  channel->producer = producer;
}

void channel_register_consumer(channel_t channel, uint8_t index, task_t consumer) {
  assert(channel->consumer == NULL);
  assert(index < consumer->rxCount);
  channel->consumerIndex = index;
  channel->consumer = consumer;
}

void channel_notify_producer(channel_t channel) {
  if (channel->producer) {
    task_unblock_tx(channel->producer, channel->producerIndex);
  }
}

void channel_notify_consumer(channel_t channel) {
  if (channel->consumer) {
    task_unblock_rx(channel->consumer, channel->consumerIndex);
  }
}
